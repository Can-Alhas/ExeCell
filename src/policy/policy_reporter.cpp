#include <execell/policy/policy_reporter.hpp>

namespace execell::policy {

void Reporter::report(const event::Event& event)
{
    downstream_.report(event);
    if (engine_.evaluate(event) == Decision::deny) {
        denied_ = true;
        const auto& violation = engine_.violations().back();
        downstream_.report(event::PolicyViolation{
            .rule = violation.rule,
            .resource = violation.resource,
            .context = std::visit([](const auto& value) {
                return value.context;
            }, event)
        });
    }
}

} // namespace execell::policy
