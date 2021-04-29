//
//  Copyright © 2020 Anbion. All rights reserved.
//

import Foundation
import JWTKit
import Crypto

struct MembershipClaims: Claims {
    let jti: JWTId
    let iss: Issuer
    let sub: UserId
    let iat: IssuedAtClaim
    let exp: ExpirationClaim
    let groupId: GroupId
    let admin: Bool
    
    var hash: String {
        var hasher = SHA256.init()
        hasher.update(data: jti.uuidString.data(using: .utf8)!)
        hasher.update(data: iss.description.data(using: .utf8)!)
        let digest = hasher.finalize()
        return digest.compactMap { String(format: "%02x", $0) }.joined()
    }
    
    init(jti: JWTId, iss: Issuer, sub: UserId, iat: Date, exp: Date, groupId: GroupId, admin: Bool) {
        self.jti = jti
        self.iss = iss
        self.sub = sub
        self.iat = IssuedAtClaim(value: iat)
        self.exp = ExpirationClaim(value: exp)
        self.groupId = groupId
        self.admin = admin
    }

    enum Issuer: Codable, Equatable, CustomStringConvertible {
        case server
        case user(UserId)

        var description: String {
            switch self {
            case .server:
                return "server"
            case .user(let userId):
                return userId.uuidString
            }
        }

        enum CodingKeys: String, CodingKey {
            case server
            case user
        }

        init(from decoder: Decoder) throws {
            let rawString = try decoder.singleValueContainer().decode(String.self)
            
            if rawString == "server" {
                self = .server
            } else {
                guard let userId = UserId(uuidString: rawString) else {
                    throw CertificateValidationError.invalidClaims
                }
                self = .user(userId)
            }
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(description)
        }
    }
}
