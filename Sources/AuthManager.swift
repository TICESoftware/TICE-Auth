//
//  Copyright © 2020 Anbion. All rights reserved.
//

import Foundation
import JWTKit
import Logging

public enum CryptoManagerError: Error, CustomStringConvertible {
    case initializationFailed(Error)
    case invalidMessageSignature
    case couldNotAccessSignedInUser
    case encryptionError
    case decryptionError(Error?)
    case discardedObsoleteMessage
    case hashingError
    case conversationNotInitialized
    case maxSkipExceeded
    case tokenGenerationFailed
    case invalidKey
    case serializationError(Error)
    case certificateValidationFailed(Error)
    case oneTimePrekeyMissing
    case cryptoStoreNotFound

    public var description: String {
        switch self {
        case .initializationFailed(let error): return "Initialization failed. Reason: \(String(describing: error))"
        case .invalidMessageSignature: return "Invalid message signature"
        case .couldNotAccessSignedInUser: return "could not access signed in user"
        case .encryptionError: return "Encryption failed"
        case .decryptionError(let error): return "Decryption failed. Reason: \(error.map { String(describing: $0) } ?? "None")"
        case .discardedObsoleteMessage: return "Discarded obsolete message."
        case .hashingError: return "Hashing failed"
        case .conversationNotInitialized: return "Conversation with user not initialized yet."
        case .maxSkipExceeded: return "Skipped too many messages. Ratchet step required."
        case .tokenGenerationFailed: return "Could not generate token."
        case .invalidKey: return "Invalid key"
        case .serializationError(let error): return String(describing: error)
        case .certificateValidationFailed(let error): return "Certificate validation failed. Reason: \(String(describing: error))"
        case .oneTimePrekeyMissing: return "No one-time prekey present."
        case .cryptoStoreNotFound: return "No crypto store found."
        }
    }
}

public enum CertificateValidationError: Error, CustomStringConvertible {
    case invalidSignature
    case invalidMembership
    case invalidClaims
    case revoked
    case expired(String)

    public var description: String {
        switch self {
        case .invalidSignature: return "Invalid signature"
        case .invalidMembership: return "Invalid membership"
        case .invalidClaims: return "Invalid claims"
        case .revoked: return "Certificate is revoked"
        case .expired(let reason): return "Certificate not valid anymore/yet. \(reason)"
        }
    }
}

public class AuthManager {

    public static let jwtValidationLeeway: TimeInterval = 5 // KEEP
    public let certificatesValidFor: TimeInterval = 60*60*24*30*12
    let logger: Logger

    public init(logger: Logger) {
        self.logger = logger
    }

    // MARK: Membership certificates

    public func createUserSignedMembershipCertificate(userId: UserId, groupId: GroupId, admin: Bool, signerUserId: UserId, signerPrivateSigningKey: PrivateKey) throws -> Certificate {
        return try createMembershipCertificate(jwtId: UUID(), userId: userId, groupId: groupId, admin: admin, issuer: .user(signerUserId), signingKey: try ECDSAKey.private(pem: signerPrivateSigningKey))
    }

    public func createServerSignedMembershipCertificate(jwtId: JWTId = UUID(), userId: UserId, groupId: GroupId, admin: Bool, signingKey: ECDSAKey) throws -> Certificate {
        return try createMembershipCertificate(jwtId: jwtId, userId: userId, groupId: groupId, admin: admin, issuer: .server, signingKey: signingKey)
    }

    private func createMembershipCertificate(jwtId: JWTId, userId: UserId, groupId: GroupId, admin: Bool, issuer: MembershipClaims.Issuer, signingKey: ECDSAKey) throws -> Certificate {
        let issueDate = Date()
        
        let claims = MembershipClaims(jti: jwtId, iss: issuer, sub: userId, iat: issueDate, exp: issueDate.addingTimeInterval(certificatesValidFor), groupId: groupId, admin: admin)
        
        let jwtSigner = JWTSigner.es512(key: signingKey)
        let jwt = try jwtSigner.sign(claims)
        return try jwtRSTojwtAsn1(jwt)
    }

    private func validate(certificate: Certificate, userId: UserId, groupId: GroupId, admin: Bool, issuer: MembershipClaims.Issuer, publicKey: PublicKey) throws {
        let signer = try JWTSigner.es512(key: .public(pem: publicKey))
        let jwt = signatureType(of: certificate) == .rs ? certificate : try jwtAsn1TojwtRS(certificate)
        
        do {
            let claims = try signer.verify(jwt, as: MembershipClaims.self)
            try claims.validateClaims()
            guard claims.groupId == groupId,
                claims.sub == userId,
                (!admin || claims.admin) else {
                throw CryptoManagerError.certificateValidationFailed(CertificateValidationError.invalidMembership)
            }

            guard claims.iss == issuer else {
                throw CryptoManagerError.certificateValidationFailed(CertificateValidationError.invalidClaims)
            }
        } catch {
            if error is CryptoManagerError {
                throw error
            } else {
                if let jwtError = error as? JWTError {
                    var certError: CertificateValidationError
                    switch jwtError {
                    case let .claimVerificationFailure(name: name, reason: reason):
                        if name == "exp" || name == "iat" {
                            certError = .expired(reason)
                        } else {
                            certError = .invalidClaims
                        }
                    case .signatureVerifictionFailed:
                        certError = .invalidSignature
                    default:
                        certError = .invalidClaims
                    }
                    throw CryptoManagerError.certificateValidationFailed(certError)
                } else {
                    throw error
                }
            }
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
