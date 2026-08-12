#include <execell/analyze/analyze.hpp>

#include <execell/report/json_reporter.hpp>
#include <execell/report/terminal_reporter.hpp>
#include <execell/policy/policy_reporter.hpp>
#include <execell/trace/tracer.hpp>

#include <fstream>
#include <iostream>
#include <fcntl.h>
#include <sstream>
#include <utility>
#include <unistd.h>

namespace execell::analyze {
namespace {

class Reporter final : public report::Reporter {
public:
    Reporter(report::Summary& summary, report::JsonReporter& json)
        : summary_{summary}, json_{json} {}
    void report(const event::Event& event) override {
        summary_.report(event);
        json_.report(event);
    }
private:
    report::Summary& summary_;
    report::JsonReporter& json_;
};

std::filesystem::path session_path()
{
    const auto path = std::filesystem::temp_directory_path() /
        ("execell-session-" + std::to_string(static_cast<long long>(::getpid())));
    std::error_code error;
    std::filesystem::create_directories(path, error);
    return error ? std::filesystem::path{} : path;
}

void string_json(std::ostream& output, std::string_view value)
{
    output << '"';
    for (const char c : value) {
        if (c == '"' || c == '\\') output << '\\';
        if (c == '\n') output << "\\n";
        else if (c == '\r') output << "\\r";
        else if (c == '\t') output << "\\t";
        else output << c;
    }
    output << '"';
}

risk::Assessment assessment(const report::Summary& summary,
                            const policy::Reporter& policy,
                            int status, bool timed_out, bool output_limited)
{
    risk::Engine engine;
    for (const auto& violation : policy.engine().violations())
        engine.reject("policy_violation", violation.rule + ": " + violation.resource);
    if (summary.network_attempts != 0U)
        engine.add("network_activity", 20, "target attempted network activity");
    if (summary.processes_spawned != 0U)
        engine.add("child_process", 5, "target spawned a child process");
    if (summary.failures != 0U)
        engine.add("failed_syscall", 10, "target generated failed system calls");
    if (timed_out) engine.reject("timeout", "analysis wall-clock limit exceeded");
    if (output_limited) engine.reject("output_limit", "analysis output limit exceeded");
    if (status != 0) engine.reject("target_failure", "target exited with status " + std::to_string(status));
    return engine.assess();
}

std::string_view verdict(const risk::Assessment& value) noexcept
{
    return value.action == risk::Action::audit ? "review" : risk::to_string(value.action);
}

} // namespace

Result run(const std::vector<std::string>& args, const Options& options)
{
    Result result;
    result.session = session_path();
    if (args.empty() || result.session.empty()) return result;

    std::ostringstream events;
    report::JsonReporter json_reporter{events};
    Reporter downstream{result.summary, json_reporter};
    policy::Reporter policy{options.policy, downstream};
    if (options.sandbox) {
        result.attestation = sandbox::attestation(options.sandbox_config);
        const auto captured = sandbox::run_captured(args, options.sandbox_config,
                                                    options.timeout, options.output_limit);
        result.exit_status = captured.status;
        result.timed_out = captured.timed_out;
        result.output_limited = captured.output_limited;
    } else {
        result.attestation = "backend=ptrace; sandbox=false; policy=observer";
        std::vector<char*> argv;
        argv.reserve(args.size() + 1U);
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        argv.push_back(nullptr);
        const int saved_stdout = options.format == Format::json ? ::dup(STDOUT_FILENO) : -1;
        const int quiet_stdout = options.format == Format::json
            ? ::open("/dev/null", O_WRONLY | O_CLOEXEC) : -1;
        if (options.format == Format::json && (saved_stdout < 0 || quiet_stdout < 0 ||
                                               ::dup2(quiet_stdout, STDOUT_FILENO) < 0)) {
            if (quiet_stdout >= 0) ::close(quiet_stdout);
            if (saved_stdout >= 0) ::close(saved_stdout);
            result.exit_status = 125;
        } else {
            result.exit_status = trace::run(argv[0], argv.data(), policy);
            if (options.format == Format::json) {
                (void)::dup2(saved_stdout, STDOUT_FILENO);
                ::close(quiet_stdout);
                ::close(saved_stdout);
            }
        }
    }
    json_reporter.finish();
    result.events_json = events.str();
    result.assessment = assessment(result.summary, policy, result.exit_status,
                                   result.timed_out, result.output_limited);
    for (auto finding : result.assessment.findings) {
        if (finding.id == "policy_violation") {
            if (!policy.engine().violations().empty()) {
                const auto& violation = policy.engine().violations().front();
                finding.resource = violation.resource;
                finding.pid = violation.context.pid;
                finding.sequence = violation.context.sequence;
            }
            result.policy_findings.push_back(std::move(finding));
        } else {
            result.observed_findings.push_back(std::move(finding));
        }
    }
    const auto append_event = [&](std::string_view type) {
        if (result.events_json.size() < 2U) return;
        result.events_json.pop_back();
        if (result.events_json != "[") result.events_json.push_back(',');
        result.events_json += "{\"schema_version\":1,\"type\":\"";
        result.events_json += type;
        result.events_json += "\",\"pid\":0,\"sequence\":0}]";
    };
    if (result.timed_out) append_event("analysis.timeout");
    if (result.output_limited) append_event("analysis.output_limit");
    std::ofstream{result.session / "events.json"} << result.events_json;
    std::ofstream{result.session / "attestation.txt"} << result.attestation << '\n';
    std::ofstream summary{result.session / "summary.json"};
    summary << json(result) << '\n';
    return result;
}

void print(const Result& result)
{
    result.summary.print(std::cout);
    std::cout << "Verdict: " << verdict(result.assessment) << '\n'
              << "Risk level: " << risk::to_string(result.assessment.level) << '\n'
              << "Risk score: " << result.assessment.score << '\n'
              << "Session: " << result.session << '\n'
              << "Attestation: " << result.attestation << '\n'
              << "Observed findings: " << result.observed_findings.size() << '\n'
              << "Policy findings: " << result.policy_findings.size() << '\n'
              << "Findings:\n";
    for (const auto& finding : result.assessment.findings)
        std::cout << "- " << finding.id << " (" << finding.weight << "): "
                  << finding.explanation << '\n';
}

std::string json(const Result& result)
{
    std::ostringstream output;
    output << "{\"schema_version\":2,\"verdict\":";
    string_json(output, verdict(result.assessment));
    output << ",\"risk_level\":";
    string_json(output, risk::to_string(result.assessment.level));
    output << ",\"risk_score\":" << result.assessment.score
           << ",\"exit_status\":" << result.exit_status
           << ",\"timed_out\":" << (result.timed_out ? "true" : "false")
           << ",\"output_limited\":" << (result.output_limited ? "true" : "false")
           << ",\"session\":";
    string_json(output, result.session.string());
    output << ",\"attestation\":";
    string_json(output, result.attestation);
    output << ",\"observed_findings\":[";
    for (std::size_t i = 0; i < result.observed_findings.size(); ++i) {
        if (i != 0U) output << ',';
        const auto& finding = result.observed_findings[i];
        output << "{\"id\":"; string_json(output, finding.id);
        output << ",\"weight\":" << finding.weight << ",\"explanation\":";
        string_json(output, finding.explanation); output << '}';
    }
    output << "],\"policy_findings\":[";
    for (std::size_t i = 0; i < result.policy_findings.size(); ++i) {
        if (i != 0U) output << ',';
        const auto& finding = result.policy_findings[i];
        output << "{\"id\":"; string_json(output, finding.id);
        output << ",\"weight\":" << finding.weight << ",\"explanation\":";
        string_json(output, finding.explanation); output << '}';
    }
    output << ']';
    output << ",\"findings\":[";
    for (std::size_t i = 0; i < result.assessment.findings.size(); ++i) {
        if (i != 0U) output << ',';
        const auto& finding = result.assessment.findings[i];
        output << "{\"id\":"; string_json(output, finding.id);
        output << ",\"resource\":"; string_json(output, finding.resource);
        output << ",\"pid\":" << finding.pid << ",\"sequence\":" << finding.sequence
               << ",\"weight\":" << finding.weight << ",\"explanation\":";
        string_json(output, finding.explanation);
        output << '}';
    }
    output << "],\"events\":" << result.events_json << '}';
    return output.str();
}

} // namespace execell::analyze
