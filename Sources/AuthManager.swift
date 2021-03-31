//
//  Copyright © 2020 Anbion. All rights reserved.
//

import Foundation
import JWTKit
import Logging

//public enum AuthenticationError: Error, CustomStringConvertible {
//    case
//}

public class AuthManager {

    public static let jwtValidationLeeway: TimeInterval = 5 // KEEP
    public let certificatesValidFor: TimeInterval = 60 * 60 * 24 * 30 * 12
    let logger: Logger

    public init(logger: Logger) {
        self.logger = logger
    }

    // MARK: Membership certificates

    public func createUserSignedMembershipCertificate(userId: UserId, groupId: GroupId, admin: Bool, signerUserId: UserId, signerPrivateSigningKey: PrivateKey) throws -> Certificate {
        try createMembershipCertificate(jwtId: UUID(), userId: userId, groupId: groupId, admin: admin, issuer: .user(signerUserId), signingKey: try ECDSAKey.private(pem: signerPrivateSigningKey))
    }

    public func createServerSignedMembershipCertificate(jwtId: JWTId = UUID(), userId: UserId, groupId: GroupId, admin: Bool, signingKey: ECDSAKey) throws -> Certificate {
        try createMembershipCertificate(jwtId: jwtId, userId: userId, groupId: groupId, admin: admin, issuer: .server, signingKey: signingKey)
    }

    private func createMembershipCertificate(jwtId: JWTId, userId: UserId, groupId: GroupId, admin: Bool, issuer: MembershipClaims.Issuer, signingKey: ECDSAKey) throws -> Certificate {
        let issueDate = Date()
        
        let claims = MembershipClaims(jti: jwtId, iss: issuer, sub: userId, iat: issueDate, exp: issueDate.addingTimeInterval(certificatesValidFor), groupId: groupId, admin: admin)
        
        let jwtSigner = JWTSigner.es512(key: signingKey)
        let jwt = try jwtSigner.sign(claims)
        return try jwtRSTojwtAsn1(jwt)
    }
    
    public func validateUserSignedMembershipCertificate(certificate: Certificate, userId: UserId, groupId: GroupId, admin: Bool, publicKey: PublicKey) throws {
        try validate(certificate: certificate, userId: userId, groupId: groupId, admin: admin, issuer: .user(userId), publicKey: publicKey)
    }
    
    public func validateServerSignedMembershipCertificate(certificate: Certificate, userId: UserId, groupId: GroupId, admin: Bool, publicKey: PublicKey) throws {
        try validate(certificate: certificate, userId: userId, groupId: groupId, admin: admin, issuer: .server, publicKey: publicKey)
    }

    private func validate(certificate: Certificate, userId: UserId, groupId: GroupId, admin: Bool, issuer: MembershipClaims.Issuer, publicKey: PublicKey) throws {
        let signer = try JWTSigner.es512(key: .public(pem: publicKey))
        let jwt = signatureType(of: certificate) == .rs ? certificate : try jwtAsn1TojwtRS(certificate)
        
        let claims: MembershipClaims
        do {
            claims = try signer.verify(jwt, as: MembershipClaims.self)
            try claims.validateClaims()
        } catch JWTError.claimVerificationFailure(name: let name, reason: _) {
            switch name {
            case "exp": throw CertificateValidationError.expired
            case "iat": throw CertificateValidationError.issuedInFuture
            default: throw CertificateValidationError.invalidClaims
            }
        }
        
        guard claims.groupId == groupId,
              claims.sub == userId,
              (!admin || claims.admin) else {
            throw CertificateValidationError.invalidMembership
        }
        
        guard claims.iss == issuer else {
            throw CertificateValidationError.invalidClaims
        }
    }
    
    public func remainingValidityTime(certificate: Certificate) throws -> TimeInterval {
        let claims = try jwtPayload(certificate, as: MembershipClaims.self)
        guard let exp = claims.exp else {
            return 0
        }
        return exp.value.timeIntervalSince(Date())
    }

    // MARK: Auth signature

    public func generateAuthHeader(signingKey: PrivateKey, userId: UserId) throws -> Certificate {
        return try generateAuthHeader(signingKey: try ECDSAKey.private(pem: signingKey), userId: userId)
    }

    public func generateAuthHeader(signingKey: ECDSAKey, userId: UserId) throws -> Certificate {
        let issueDate = Date()
        let claims = AuthHeaderClaims(iss: userId, iat: issueDate, exp: issueDate.addingTimeInterval(120), nonce: maybeUnsafeRandomNonce(bytes: 16))
        let jwtSigner = JWTSigner.es512(key: signingKey)
        let jwt = try jwtSigner.sign(claims)
        return try jwtRSTojwtAsn1(jwt)
    }

    public func parseAuthHeaderClaims(_ authHeader: Certificate, leeway: TimeInterval? = nil) throws -> UserId {
        let claims = try jwtPayload(authHeader, as: AuthHeaderClaims.self)
        try claims.verify()
        return claims.iss
    }

    public func verify(authHeader: Certificate, publicKey: PublicKey) -> Bool {
        do {
            let signer = try JWTSigner.es512(key: .public(pem: publicKey))
            let authHeaderRS = signatureType(of: authHeader) == .rs ? authHeader : try jwtAsn1TojwtRS(authHeader)
            _ = try signer.verify(authHeaderRS, as: AuthHeaderClaims.self)
            return true
        } catch {
            return false
        }
    }
    
    public func maybeUnsafeRandomNonce(bytes: Int) -> Data {
        var array: [UInt8] = .init(repeating: 0, count: bytes)
        (0..<bytes).forEach { array[$0] = UInt8.random(in: UInt8.min ... UInt8.max) }
        return Data(array)
    }
}
