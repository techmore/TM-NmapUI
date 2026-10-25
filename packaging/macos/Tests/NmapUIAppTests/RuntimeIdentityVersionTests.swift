import Testing
@testable import NmapUIApp

@Suite("Product version identity")
struct RuntimeIdentityVersionTests {
    @Test("product identity retains the raw calendar release rather than numeric bundle metadata")
    func prefersRawVersion() {
        #expect(RuntimeIdentity.productVersion(info: [
            "NmapUIProductVersion": "v2026.3.14.00_10",
            "CFBundleShortVersionString": "2026.3.14"
        ]) == "v2026.3.14.00_10")
    }

    @Test("unbundled and older apps retain the marketing version fallback")
    func fallsBack() {
        #expect(RuntimeIdentity.productVersion(info: ["CFBundleShortVersionString": "1.0.0"]) == "1.0.0")
        #expect(RuntimeIdentity.productVersion(info: [:]) == "unknown")
    }
}
