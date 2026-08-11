#include <execell/package/network.hpp>
#include <execell/risk/risk.hpp>

#include <cassert>

int main() {
    using execell::package::network::allowed;
    assert(execell::package::network::valid_mirror("https://mirror.example/repo"));
    assert(!execell::package::network::valid_mirror("file:///tmp/repo"));
    assert(allowed("https://mirror.example:443/pkg", {"https://mirror.example/repo"}));
    assert(!allowed("http://other.example/pkg", {"https://mirror.example/repo"}));
    execell::risk::Engine engine;
    engine.add("scripts", 15, "maintainer scripts execute package-provided code");
    auto assessment = engine.assess();
    assert(assessment.level == execell::risk::Level::low);
    assert(assessment.action == execell::risk::Action::allow);
    engine.reject("signature", "signature verification failed");
    assessment = engine.assess();
    assert(assessment.level == execell::risk::Level::critical);
    assert(assessment.action == execell::risk::Action::reject);
    execell::risk::Engine weighted;
    weighted.add("medium", 25, "medium factor");
    assert(weighted.assess().level == execell::risk::Level::medium);
    weighted.add("high", 25, "high factor");
    assert(weighted.assess().level == execell::risk::Level::high);
}
