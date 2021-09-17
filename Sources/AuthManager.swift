//
//  Copyright © 2020 Anbion. All rights reserved.
//

import Foundation
import JWTKit
import Logging

public class AuthManager {

    public static let jwtValidationLeeway: TimeInterval = 60
    public let certificatesValidFor: TimeInterval = 60 * 60 * 24 * 30 * 12
    let logger: Logger

    public init(logger: Logger) {
        self.logger = logger
    }

    // MARK: Membership certificates

    public func createUserSignedMembershipCertificate(userId: UserId, groupId: GroupId, admin: Bool, issuerUserId: UserId, signingKey: PrivateKey) throws -> Certificate {
        try createMembershipCertificate(jwtId: UUID(), userId: userId, groupId: groupId, admin: admin, issuer: .user(issuerUserId), signingKey: try ECDSAKey.private(pem: signingKey))
    }

    public func createServerSignedMembershipCertificate(jwtId: JWTId = UUID(), userId: UserId, groupId: GroupId, admin: Bool, signingKey: ECDSAKey) throws -> Certificate {
        try createMembershipCertificate(jwtId: jwtId, userId: userId, groupId: groupId, admin: admin, issuer: .server, signingKey: signingKey)
    }

    private func createMembershipCertificate(jwtId: JWTId, userId: UserId, groupId: GroupId, admin: Bool, issuer: MembershipClaims.Issuer, signingKey: ECDSAKey) throws -> Certificate {
        let issueDate = Date()
        
        let claims = MembershipClaims(jti: jwtId, iss: issuer, sub: userId, iat: issueDate, exp: issueDate.addingTimeInterval(certificatesValidFor), groupId: groupId, admin: admin)
        
        return try createASN1Certificate(claims: claims, signingKey: signingKey)
    }
    
    public func validateUserSignedMembershipCertificate(certificate: Certificate, userId: UserId, groupId: GroupId, admin: Bool, issuerUserId: UserId, publicKey: PublicKey) throws {
        try validate(certificate: certificate, userId: userId, groupId: groupId, admin: admin, issuer: .user(issuerUserId), publicKey: .public(pem: publicKey))
    }
    
    public func validateUserSignedMembershipCertificate(certificate: Certificate, userId: UserId, groupId: GroupId, admin: Bool, issuerUserId: UserId, publicKey: ECDSAKey) throws {
        try validate(certificate: certificate, userId: userId, groupId: groupId, admin: admin, issuer: .user(issuerUserId), publicKey: publicKey)
    }
    
    public func validateServerSignedMembershipCertificate(certificate: Certificate, userId: UserId, groupId: GroupId, admin: Bool, publicKey: PublicKey) throws {
        try validate(certificate: certificate, userId: userId, groupId: groupId, admin: admin, issuer: .server, publicKey: .public(pem: publicKey))
    }
    
    public func validateServerSignedMembershipCertificate(certificate: Certificate, userId: UserId, groupId: GroupId, admin: Bool, publicKey: ECDSAKey) throws {
        try validate(certificate: certificate, userId: userId, groupId: groupId, admin: admin, issuer: .server, publicKey: publicKey)
    }

    private func validate(certificate: Certificate, userId: UserId, groupId: GroupId, admin: Bool, issuer: MembershipClaims.Issuer, publicKey: ECDSAKey) throws {
        let claims: MembershipClaims = try extractAndVerifyClaims(certificate: certificate, publicKey: publicKey)
        
        guard claims.groupId == groupId,
              claims.sub == userId,
              (!admin || claims.admin) else {
            throw CertificateValidationError.invalidMembership
        }
        
        guard claims.iss == issuer else {
            throw CertificateValidationError.invalidClaims
        }
    }
    
    public func membershipCertificateCreationDate(certificate: Certificate) throws -> Date {
        try creationDate(certificate: certificate, claimsType: MembershipClaims.self)
    }
    
    public func membershipCertificateExpirationDate(certificate: Certificate) throws -> Date {
        try expirationDate(certificate: certificate, claimsType: MembershipClaims.self)
    }
    
    public func renewMembershipCertificate(certificate: Certificate, signingKey: ECDSAKey) throws -> Certificate {
        let claims: MembershipClaims = try jwtPayload(certificate)
        return try createServerSignedMembershipCertificate(jwtId: claims.jti, userId: claims.sub, groupId: claims.groupId, admin: claims.admin, signingKey: signingKey)
    }
    
    public func serverSignedMembershipCertificateRevocableBy(userId: UserId, certificate: Certificate, publicKey: ECDSAKey) -> Bool {
        do {
            let claims: MembershipClaims = try extractAndVerifyClaims(certificate: certificate, publicKey: publicKey)
            return claims.iss == .server && claims.sub == userId
        } catch {
            return false
        }
    }
    
    public func membershipClaimsHash(certificate: Certificate) throws -> String {
        let claims: MembershipClaims = try jwtPayload(certificate)
        return claims.hash
    }
    
    public func claimedGroupId(certificate: Certificate) throws -> GroupId {
        let membershipClaims: MembershipClaims = try jwtPayload(certificate)
        return membershipClaims.groupId
    }
    
    public func claimedAdmin(certificate: Certificate) throws -> Bool {
        let membershipClaims: MembershipClaims = try jwtPayload(certificate)
        return membershipClaims.admin
    }
    
    // MARK: Key signature
    
    public func createKeyCertificate(issuer: UserId, publicKey: PublicKey, signingKey: PrivateKey) throws -> Certificate {
        let issueDate = Date()
        let claims = KeyClaims(iss: issuer, iat: issueDate, exp: Date().addingTimeInterval(certificatesValidFor), publicKey: publicKey)
        
        return try createASN1Certificate(claims: claims, signingKey: try ECDSAKey.private(pem: signingKey))
    }
    
    public func validateKeyCertificate(certificate: Certificate, issuer: UserId, publicKey: PublicKey) throws {
        let claims: KeyClaims = try extractAndVerifyClaims(certificate: certificate, publicKey: publicKey)
        
        guard claims.iss == issuer else {
            throw CertificateValidationError.invalidClaims
        }
    }
    
    public func keyCertificateExpirationDate(certificate: Certificate) throws -> Date {
        try expirationDate(certificate: certificate, claimsType: KeyClaims.self)
    }

    // MARK: Auth signature

    public func generateAuthHeader(signingKey: PrivateKey, userId: UserId) throws -> Certificate {
        return try generateAuthHeader(signingKey: try ECDSAKey.private(pem: signingKey), userId: userId)
    }

    internal func generateAuthHeader(signingKey: ECDSAKey, userId: UserId) throws -> Certificate {
        let issueDate = Date()
        let claims = AuthHeaderClaims(iss: userId, iat: issueDate, exp: issueDate.addingTimeInterval(120), nonce: maybeUnsafeRandomNonce(bytes: 16))
        return try createASN1Certificate(claims: claims, signingKey: signingKey)
    }

    public func claimedUserId(_ authHeader: Certificate) throws -> UserId {
        let authHeaderClaims: AuthHeaderClaims = try jwtPayload(authHeader)
        return authHeaderClaims.iss
    }

    public func verify(authHeader: Certificate, publicKey: PublicKey) -> Bool {
        do {            
            _ = try extractAndVerifyClaims(certificate: authHeader, publicKey: publicKey) as AuthHeaderClaims
            return true
        } catch {
            logger.debug("Auth header verification failed: \(error)")
            return false
        }
    }
    
    internal func maybeUnsafeRandomNonce(bytes: Int) -> Data {
        var array: [UInt8] = .init(repeating: 0, count: bytes)
        (0..<bytes).forEach { array[$0] = UInt8.random(in: UInt8.min ... UInt8.max) }
        return Data(array)
    }
    
    // MARK: Generic
    
    private func createASN1Certificate<Payload: JWTPayload>(claims: Payload, signingKey: ECDSAKey) throws -> Certificate {
        let jwtSigner = JWTSigner.es512(key: signingKey)
        let jwt = try jwtSigner.sign(claims)
        return try jwtRSTojwtAsn1(jwt)
    }
    
    private func creationDate<T: Claims>(certificate: Certificate, claimsType: T.Type) throws -> Date {
        let claims: T = try jwtPayload(certificate)
        return claims.iat.value
    }
    
    private func expirationDate<T: Claims>(certificate: Certificate, claimsType: T.Type) throws -> Date {
        let claims: T = try jwtPayload(certificate)
        return claims.exp.value
    }
    
    private func extractAndVerifyClaims<T: Claims>(certificate: Certificate, publicKey: PublicKey) throws -> T {
        return try extractAndVerifyClaims(certificate: certificate, publicKey: .public(pem: publicKey))
    }
    
    private func extractAndVerifyClaims<T: Claims>(certificate: Certificate, publicKey: ECDSAKey) throws -> T {
        let signer = JWTSigner.es512(key: publicKey)
        let jwt = signatureType(of: certificate) == .rs ? certificate : try jwtAsn1TojwtRS(certificate)
        
        do {
            return try signer.verify(jwt, as: T.self)
        } catch JWTError.claimVerificationFailure(name: let name, reason: _) {
            switch name {
            case "exp": throw CertificateValidationError.expired
            case "iat": throw CertificateValidationError.issuedInFuture
            default: throw CertificateValidationError.invalidClaims
            }
        } catch JWTError.signatureVerifictionFailed {
            throw CertificateValidationError.invalidSignature
        }
    }
}
