import XCTest
import Logging
import JWTKit
import Crypto

@testable import TICEAuth

class TICEAuthTests: XCTestCase {
    let authManager = AuthManager(logger: Logger(label: "software.tice.TICECrypto.tests", factory: TestLogHandler.init))
    
    let groupId = UUID(uuidString: "C621E1F8-C36C-495A-93FC-0C247A3E6E5F")!
    let userId = UUID(uuidString: "D621E1F8-C36C-495A-93FC-0C247A3E6E5F")!
    let adminUserId = UUID(uuidString: "E621E1F8-C36C-495A-93FC-0C247A3E6E5F")!
    let randomUUID = UUID(uuidString: "F621E1F8-C36C-495A-93FC-0C247A3E6E5F")!
    
    let privateKey = """
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAgHEAuA8gfGnNUqYGYo2QgShxhd6MFxfig/o0KKPq9MScpf8/AMxv
kVS5sJxCW2K7lnSs8aynlXcQrfAmt4ybfoOgBwYFK4EEACOhgYkDgYYABAAVumr0
A4m3key2NeSJQ9f5ykPpOCSd3lJ54PW7cmV9a5jkRJx+65asndU/4Hk4IoiZ8GXa
fndDggKDYPfg3VvzTADhw9XTa2G6LP3ubZI0jWM4MnT1AeU1CqFtzukXGHCAAhtM
tldpHfIHDhRsa3tH9WSkL7EdbH2bWifefkxpiEBM9w==
-----END EC PRIVATE KEY-----
""".data(using: .utf8)!
    
    let publicKey = """
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAFbpq9AOJt5HstjXkiUPX+cpD6Tgk
nd5SeeD1u3JlfWuY5EScfuuWrJ3VP+B5OCKImfBl2n53Q4ICg2D34N1b80wA4cPV
02thuiz97m2SNI1jODJ09QHlNQqhbc7pFxhwgAIbTLZXaR3yBw4UbGt7R/VkpC+x
HWx9m1on3n5MaYhATPc=
-----END PUBLIC KEY-----
""".data(using: .utf8)!
    
    let otherPrivateKey = """
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAgEcmhFfsbLq89YPUVvd6iE/5AUm7DhWLCSsbE8eV2jLK/fUhkpjc
uH1IOuxyVordJZ8J2zadS2090RZNKWnLwXmgBwYFK4EEACOhgYkDgYYABACOapxD
mLxAqA71aKSwQFeuk7wuWv5Y9kK+0fH1DMQQQth5RiGuXwXU6dZeDlBV4rHTebK7
ikwHwjVUL9zfXfFDhAHRMQJLMlND2hZZmQ3a98Zcvg6WVIAnl4jzs9p6FliyB6ok
1rOCKQowwe1POP7qefUs5u0VzovIBdhfmfFqris2Ng==
-----END EC PRIVATE KEY-----
""".data(using: .utf8)!
    
    let otherPublicKey = """
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAjmqcQ5i8QKgO9WiksEBXrpO8Llr+
WPZCvtHx9QzEEELYeUYhrl8F1OnWXg5QVeKx03myu4pMB8I1VC/c313xQ4QB0TEC
SzJTQ9oWWZkN2vfGXL4OllSAJ5eI87PaehZYsgeqJNazgikKMMHtTzj+6nn1LObt
Fc6LyAXYX5nxaq4rNjY=
-----END PUBLIC KEY-----
""".data(using: .utf8)!
    
    var privateECDSAKey: ECDSAKey {
        try! ECDSAKey.private(pem: privateKey)
    }
    
    // MARK: Membership certificate
    
    func testMembershipCertificateValidation() throws {
        let userCert = try authManager.createUserSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuerUserId: adminUserId, signingKey: privateKey)
        let serverCert = try authManager.createServerSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, signingKey: privateECDSAKey)
        
        try authManager.validateUserSignedMembershipCertificate(certificate: userCert, userId: userId, groupId: groupId, admin: true, issuerUserId: adminUserId, publicKey: publicKey)
        try authManager.validateServerSignedMembershipCertificate(certificate: serverCert, userId: userId, groupId: groupId, admin: true, publicKey: publicKey)
    }
    
    func testCheckMembershipOnCertificateValidation() throws {
        // Signed by user
        let userCert = try authManager.createUserSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuerUserId: adminUserId, signingKey: privateKey)
        
        XCTAssertThrowsSpecificError(try authManager.validateUserSignedMembershipCertificate(certificate: userCert, userId: randomUUID, groupId: groupId, admin: true, issuerUserId: adminUserId, publicKey: publicKey), CertificateValidationError.invalidMembership)
        XCTAssertThrowsSpecificError(try authManager.validateUserSignedMembershipCertificate(certificate: userCert, userId: userId, groupId: randomUUID, admin: true, issuerUserId: adminUserId, publicKey: publicKey), CertificateValidationError.invalidMembership)
        
        // Signed by server
        let serverCert = try authManager.createServerSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, signingKey: privateECDSAKey)
        
        XCTAssertThrowsSpecificError(try authManager.validateServerSignedMembershipCertificate(certificate: serverCert, userId: randomUUID, groupId: groupId, admin: true, publicKey: publicKey), CertificateValidationError.invalidMembership)
        XCTAssertThrowsSpecificError(try authManager.validateServerSignedMembershipCertificate(certificate: serverCert, userId: userId, groupId: randomUUID, admin: true, publicKey: publicKey), CertificateValidationError.invalidMembership)
    }
    
    func testCheckAdminFlagOnCertificateValidation() throws {
        // Signed by user
        let userCertAdmin = try authManager.createUserSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuerUserId: adminUserId, signingKey: privateKey)
        try authManager.validateUserSignedMembershipCertificate(certificate: userCertAdmin, userId: userId, groupId: groupId, admin: false, issuerUserId: adminUserId, publicKey: publicKey)
        
        let userCertNonAdmin = try authManager.createUserSignedMembershipCertificate(userId: userId, groupId: groupId, admin: false, issuerUserId: adminUserId, signingKey: privateKey)
        try authManager.validateUserSignedMembershipCertificate(certificate: userCertNonAdmin, userId: userId, groupId: groupId, admin: false, issuerUserId: adminUserId, publicKey: publicKey)
        XCTAssertThrowsSpecificError(try authManager.validateUserSignedMembershipCertificate(certificate: userCertNonAdmin, userId: userId, groupId: randomUUID, admin: true, issuerUserId: adminUserId, publicKey: publicKey), CertificateValidationError.invalidMembership)
        
        // Signed by server
        let serverCertNonAdmin = try authManager.createServerSignedMembershipCertificate(userId: userId, groupId: groupId, admin: false, signingKey: privateECDSAKey)
        try authManager.validateServerSignedMembershipCertificate(certificate: serverCertNonAdmin, userId: userId, groupId: groupId, admin: false, publicKey: publicKey)
        XCTAssertThrowsSpecificError(try authManager.validateServerSignedMembershipCertificate(certificate: serverCertNonAdmin, userId: userId, groupId: groupId, admin: true, publicKey: publicKey), CertificateValidationError.invalidMembership)
    }
    
    func testCheckSignerOnMembershipCertificateValidation() throws {
        // Signed by user
        let userCert = try authManager.createUserSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuerUserId: adminUserId, signingKey: privateKey)
        
        XCTAssertThrowsSpecificError(try authManager.validateUserSignedMembershipCertificate(certificate: userCert, userId: userId, groupId: groupId, admin: true, issuerUserId: randomUUID, publicKey: publicKey), CertificateValidationError.invalidClaims)
        XCTAssertThrowsSpecificError(try authManager.validateServerSignedMembershipCertificate(certificate: userCert, userId: userId, groupId: groupId, admin: true, publicKey: publicKey), CertificateValidationError.invalidClaims)
        
        // Signed by server
        let serverCert = try authManager.createServerSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, signingKey: privateECDSAKey)
        XCTAssertThrowsSpecificError(try authManager.validateUserSignedMembershipCertificate(certificate: serverCert, userId: userId, groupId: groupId, admin: true, issuerUserId: adminUserId, publicKey: publicKey), CertificateValidationError.invalidClaims)
    }
    
    func testValidateExpiredMembershipCertificate() throws {
        // Signed by user
        let expiredUserCert = try createMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuer: .user(adminUserId), iat: Date().advanced(by: -3600.0), exp: Date().advanced(by: -70.0), signingKey: privateECDSAKey)
        
        XCTAssertThrowsSpecificError(try authManager.validateUserSignedMembershipCertificate(certificate: expiredUserCert, userId: userId, groupId: groupId, admin: true, issuerUserId: adminUserId, publicKey: publicKey), CertificateValidationError.expired)
        
        let expiredUserCertWithLeeway = try createMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuer: .user(adminUserId), iat: Date().advanced(by: -3600.0), exp: Date().advanced(by: -50.0), signingKey: privateECDSAKey)
        
        try authManager.validateUserSignedMembershipCertificate(certificate: expiredUserCertWithLeeway, userId: userId, groupId: groupId, admin: true, issuerUserId: adminUserId, publicKey: publicKey)

        // Signed by server
        let expiredServerCert = try createMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuer: .server, iat: Date().advanced(by: -3600.0), exp: Date().advanced(by: -70.0), signingKey: privateECDSAKey)
        
        XCTAssertThrowsSpecificError(try authManager.validateServerSignedMembershipCertificate(certificate: expiredServerCert, userId: userId, groupId: groupId, admin: true, publicKey: publicKey), CertificateValidationError.expired)
        
        let expiredServerCertWithLeeway = try createMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuer: .server, iat: Date().advanced(by: -3600.0), exp: Date().advanced(by: -50.0), signingKey: privateECDSAKey)
        
        try authManager.validateServerSignedMembershipCertificate(certificate: expiredServerCertWithLeeway, userId: userId, groupId: groupId, admin: true, publicKey: publicKey)
    }
    
    func testValidateMembershipCertificateIssuedInFuture() throws {
        // Signed by user
        let userCertIssuedInFuture = try createMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuer: .user(adminUserId), iat: Date().advanced(by: 70.0), exp: Date().advanced(by: 3600.0), signingKey: privateECDSAKey)
        
        XCTAssertThrowsSpecificError(try authManager.validateUserSignedMembershipCertificate(certificate: userCertIssuedInFuture, userId: userId, groupId: groupId, admin: true, issuerUserId: adminUserId, publicKey: publicKey), CertificateValidationError.issuedInFuture)
        
        let userCertIssuedInFutureWithLeeway = try createMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuer: .user(adminUserId), iat: Date().advanced(by: 50.0), exp: Date().advanced(by: 3600.0), signingKey: privateECDSAKey)
        
        try authManager.validateUserSignedMembershipCertificate(certificate: userCertIssuedInFutureWithLeeway, userId: userId, groupId: groupId, admin: true, issuerUserId: adminUserId, publicKey: publicKey)
        
        // Signed by server
        let serverCertIssuedInFuture = try createMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuer: .server, iat: Date().advanced(by: 70.0), exp: Date().advanced(by: 3600.0), signingKey: privateECDSAKey)
        
        XCTAssertThrowsSpecificError(try authManager.validateServerSignedMembershipCertificate(certificate: serverCertIssuedInFuture, userId: userId, groupId: groupId, admin: true, publicKey: publicKey), CertificateValidationError.issuedInFuture)
        
        let serverCertIssuedInFutureWithLeeway = try createMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuer: .server, iat: Date().advanced(by: 50.0), exp: Date().advanced(by: 3600.0), signingKey: privateECDSAKey)
        
        try authManager.validateServerSignedMembershipCertificate(certificate: serverCertIssuedInFutureWithLeeway, userId: userId, groupId: groupId, admin: true, publicKey: publicKey)
    }
    
    func testMembershipCertificateRemainingValidityTime() throws {
        // Signed by user
        let userCert = try createMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuer: .user(adminUserId), iat: Date(), exp: Date().advanced(by: 3600.0), signingKey: privateECDSAKey)
        
        XCTAssertEqual(try authManager.membershipCertificateExpiresIn(certificate: userCert), 3600.0, accuracy: 0.1)
        
        // Signed by server
        let serverCert = try createMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuer: .server, iat: Date(), exp: Date().advanced(by: 3600.0), signingKey: privateECDSAKey)
        
        XCTAssertEqual(try authManager.membershipCertificateExpiresIn(certificate: serverCert), 3600.0, accuracy: 0.1)
    }
    
    func testValidateMembershipCertificateInvalidSignature() throws {
        // Signed by user
        let userCert = try authManager.createUserSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuerUserId: adminUserId, signingKey: privateKey)
        
        XCTAssertThrowsSpecificError(try authManager.validateUserSignedMembershipCertificate(certificate: userCert, userId: userId, groupId: groupId, admin: true, issuerUserId: randomUUID, publicKey: otherPublicKey), CertificateValidationError.invalidSignature)
        
        // Signed by server
        let serverCert = try authManager.createServerSignedMembershipCertificate(userId: userId, groupId: groupId, admin: true, signingKey: privateECDSAKey)
        
        XCTAssertThrowsSpecificError(try authManager.validateServerSignedMembershipCertificate(certificate: serverCert, userId: userId, groupId: groupId, admin: true, publicKey: otherPublicKey), CertificateValidationError.invalidSignature)
    }
    
    func testRevocableBy() throws {
        // Signed by user
        let userCert = try createMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuer: .user(adminUserId), iat: Date(), exp: Date().advanced(by: 3600.0), signingKey: privateECDSAKey)
        
        XCTAssertFalse(authManager.serverSignedMembershipCertificateRevocableBy(userId: adminUserId, certificate: userCert, publicKey: publicKey))
        XCTAssertFalse(authManager.serverSignedMembershipCertificateRevocableBy(userId: randomUUID, certificate: userCert, publicKey: publicKey))
        XCTAssertFalse(authManager.serverSignedMembershipCertificateRevocableBy(userId: adminUserId, certificate: userCert, publicKey: otherPublicKey))
        
        // Signed by server
        let serverCert = try createMembershipCertificate(userId: userId, groupId: groupId, admin: true, issuer: .server, iat: Date(), exp: Date().advanced(by: 3600.0), signingKey: privateECDSAKey)
        
        XCTAssertTrue(authManager.serverSignedMembershipCertificateRevocableBy(userId: userId, certificate: serverCert, publicKey: publicKey))
        XCTAssertFalse(authManager.serverSignedMembershipCertificateRevocableBy(userId: randomUUID, certificate: serverCert, publicKey: publicKey))
        XCTAssertFalse(authManager.serverSignedMembershipCertificateRevocableBy(userId: adminUserId, certificate: serverCert, publicKey: otherPublicKey))
    }
    
    func testMembershipClaimsHash() throws {
        // Signed by user
        let userCert = try createMembershipCertificate(jwtId: randomUUID, userId: userId, groupId: groupId, admin: true, issuer: .user(adminUserId), iat: Date(), exp: Date().advanced(by: 3600.0), signingKey: privateECDSAKey)
        
        XCTAssertEqual(try authManager.membershipClaimsHash(certificate: userCert), "d670431b68243ed82ce4bc056233c5be30647293a4e68d206cdfdf6e8a60c102")
        
        // Signed by server
        let serverCert = try createMembershipCertificate(jwtId: randomUUID, userId: userId, groupId: groupId, admin: true, issuer: .server, iat: Date(), exp: Date().advanced(by: 3600.0), signingKey: privateECDSAKey)
        
        XCTAssertEqual(try authManager.membershipClaimsHash(certificate: serverCert), "9f2a994004b01312fc7a2a30bb571aaa9f867c8d911a7a659fcb303d50770192")
    }
    
    // MARK: Key certificate
    
    func testKeyCertificateValidation() throws {
        let cert = try authManager.createKeyCertificate(issuer: userId, publicKey: publicKey, signingKey: privateKey)
        
        try authManager.validateKeyCertificate(certificate: cert, issuer: userId, publicKey: publicKey)
    }
    
    func testCheckSignerOnKeyCertificateValidation() throws {
        let cert = try authManager.createKeyCertificate(issuer: userId, publicKey: publicKey, signingKey: privateKey)
        
        XCTAssertThrowsSpecificError(try authManager.validateKeyCertificate(certificate: cert, issuer: randomUUID, publicKey: publicKey), CertificateValidationError.invalidClaims)
    }
    
    func testValidateExpiredKeyCertificate() throws {
        // Signed by user
        let expiredCert = try createKeyCertificate(issuer: userId, iat: Date().advanced(by: -3600.0), exp: Date().advanced(by: -70.0), publicKey: publicKey, signingKey: privateECDSAKey)
        
        XCTAssertThrowsSpecificError(try authManager.validateKeyCertificate(certificate: expiredCert, issuer: userId, publicKey: publicKey), CertificateValidationError.expired)
        
        let expiredCertWithLeeway = try createKeyCertificate(issuer: userId, iat: Date().advanced(by: -3600.0), exp: Date().advanced(by: -50.0), publicKey: publicKey, signingKey: privateECDSAKey)
        
        try authManager.validateKeyCertificate(certificate: expiredCertWithLeeway, issuer: userId, publicKey: publicKey)
    }
    
    func testValidateKeyCertificateIssuedInFuture() throws {
        // Signed by user
        let certIssuedInFuture = try createKeyCertificate(issuer: userId, iat: Date().advanced(by: 70.0), exp: Date().advanced(by: 3600.0), publicKey: publicKey, signingKey: privateECDSAKey)
        
        XCTAssertThrowsSpecificError(try authManager.validateKeyCertificate(certificate: certIssuedInFuture, issuer: userId, publicKey: publicKey), CertificateValidationError.issuedInFuture)
        
        let certIssuedInFutureWithLeeway = try createKeyCertificate(issuer: userId, iat: Date().advanced(by: 50.0), exp: Date().advanced(by: 3600.0), publicKey: publicKey, signingKey: privateECDSAKey)
        
        try authManager.validateKeyCertificate(certificate: certIssuedInFutureWithLeeway, issuer: userId, publicKey: publicKey)
    }
    
    func testKeyCertificateRemainingValidityTime() throws {
        // Signed by user
        let cert = try createKeyCertificate(issuer: userId, iat: Date(), exp: Date().advanced(by: 3600.0), publicKey: publicKey, signingKey: privateECDSAKey)
        
        XCTAssertEqual(try authManager.keyCertificateExpiresIn(certificate: cert), 3600.0, accuracy: 0.1)
    }
    
    func testValidateKeyCertificateInvalidSignature() throws {
        // Signed by user
        let cert = try authManager.createKeyCertificate(issuer: userId, publicKey: publicKey, signingKey: privateKey)
        
        XCTAssertThrowsSpecificError(try authManager.validateKeyCertificate(certificate: cert, issuer: userId, publicKey: otherPublicKey), CertificateValidationError.invalidSignature)
    }
    
    // MARK: AuthHeader
    
    func testAuthHeaderVerification() throws {
        let authHeader = try authManager.generateAuthHeader(signingKey: privateKey, userId: userId)
        XCTAssertTrue(authManager.verify(authHeader: authHeader, publicKey: publicKey))
        
        let nonce = Data([UInt8](repeating: 0, count: 16))
        let claims = AuthHeaderClaims(iss: userId, iat: Date().advanced(by: -200), exp: Date().advanced(by: -120), nonce: nonce)
        let manuallyAssembledAuthHeader = try createASN1Certificate(claims: claims, signingKey: privateECDSAKey)
        
        XCTAssertFalse(authManager.verify(authHeader: manuallyAssembledAuthHeader, publicKey: publicKey))
    }
    
    func testAuthHeaderUserIdExtraction() throws {
        let authHeader = try authManager.generateAuthHeader(signingKey: privateKey, userId: userId)
        XCTAssertEqual(try authManager.claimedUserId(authHeader), userId)
    }
    
    func testExpiredAuthHeader() throws {
        let nonce = Data([UInt8](repeating: 0, count: 16))
        let claims = AuthHeaderClaims(iss: userId, iat: Date().advanced(by: -200), exp: Date().advanced(by: -70), nonce: nonce)
        let authHeader = try createASN1Certificate(claims: claims, signingKey: privateECDSAKey)
        
        XCTAssertFalse(authManager.verify(authHeader: authHeader, publicKey: publicKey))
        
        let claimsWithLeeway = AuthHeaderClaims(iss: userId, iat: Date().advanced(by: -200), exp: Date().advanced(by: -50), nonce: nonce)
        let authHeaderWithLeeway = try createASN1Certificate(claims: claimsWithLeeway, signingKey: privateECDSAKey)
        
        XCTAssertTrue(authManager.verify(authHeader: authHeaderWithLeeway, publicKey: publicKey))
    }
    
    func testAuthHeaderIssuedInFuture() throws {
        let nonce = Data([UInt8](repeating: 0, count: 16))
        let claims = AuthHeaderClaims(iss: userId, iat: Date().advanced(by: 70), exp: Date().advanced(by: 200), nonce: nonce)
        let authHeader = try createASN1Certificate(claims: claims, signingKey: privateECDSAKey)
        
        XCTAssertFalse(authManager.verify(authHeader: authHeader, publicKey: publicKey))
        
        let claimsWithLeeway = AuthHeaderClaims(iss: userId, iat: Date().advanced(by: 50), exp: Date().advanced(by: 200), nonce: nonce)
        let authHeaderWithLeeway = try createASN1Certificate(claims: claimsWithLeeway, signingKey: privateECDSAKey)
        
        XCTAssertTrue(authManager.verify(authHeader: authHeaderWithLeeway, publicKey: publicKey))
    }
    
    func testAuthHeaderInvalidSignature() throws {
        let nonce = Data([UInt8](repeating: 0, count: 16))
        let claims = AuthHeaderClaims(iss: userId, iat: Date(), exp: Date().advanced(by: 200), nonce: nonce)
        let authHeader = try createASN1Certificate(claims: claims, signingKey: privateECDSAKey)
        
        XCTAssertFalse(authManager.verify(authHeader: authHeader, publicKey: otherPublicKey))
    }
    
    private func createMembershipCertificate(jwtId: JWTId = JWTId(), userId: UserId, groupId: GroupId, admin: Bool, issuer: MembershipClaims.Issuer, iat: Date, exp: Date, signingKey: ECDSAKey) throws -> Certificate {
        let claims = MembershipClaims(jti: jwtId, iss: issuer, sub: userId, iat: iat, exp: exp, groupId: groupId, admin: admin)
        
        return try createASN1Certificate(claims: claims, signingKey: signingKey)
    }
    
    private func createKeyCertificate(issuer: UserId, iat: Date, exp: Date, publicKey: PublicKey, signingKey: ECDSAKey) throws -> Certificate {
        let claims = KeyClaims(iss: issuer, iat: iat, exp: exp, publicKey: publicKey)
        
        return try createASN1Certificate(claims: claims, signingKey: signingKey)
    }
    
    private func createASN1Certificate<Payload: JWTPayload>(claims: Payload, signingKey: ECDSAKey) throws -> Certificate {
        let jwtSigner = JWTSigner.es512(key: signingKey)
        let jwt = try jwtSigner.sign(claims)
        return try jwtRSTojwtAsn1(jwt)
    }
}

extension XCTestCase {
    func XCTAssertThrowsSpecificError<E: Error & Equatable>(_ expression: @autoclosure () throws -> Void, _ expectedError: E, _ message: @autoclosure () -> String = "", file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try expression(), message(), file: file, line: line) { error in
            guard error as? E == expectedError else {
                XCTFail("Unexpected error: \(error). Expected: \(expectedError)")
                return
            }
        }
    }
}

struct TestLogHandler: LogHandler {
    var metadata: Logger.Metadata = [:]
    var logLevel: Logger.Level = .trace
    let identifier: String
    
    init(identifier: String) {
        self.identifier = identifier
    }
    
    subscript(metadataKey metadataKey: String) -> Logger.Metadata.Value? {
        get {
            metadata[metadataKey]
        }
        set(newValue) {
            metadata[metadataKey] = newValue
        }
    }
    
    func log(level: Logger.Level, message: Logger.Message, metadata: Logger.Metadata?, file: String, function: String, line: UInt) {
        print("TEST log: \(level) \(message) \(file) \(function) \(line)")
    }
}
