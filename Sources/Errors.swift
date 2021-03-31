//
//  Copyright © 2020 Anbion. All rights reserved.
//

import Foundation

public enum CertificateCreationError: Error, CustomStringConvertible {
    case tokenGenerationFailed
    
    public var description: String {
        switch self {
        case .tokenGenerationFailed: return "JWT could not be generated."
        }
    }
}

public enum CertificateValidationError: Error, CustomStringConvertible {
    case invalidSignature
    case invalidMembership
    case invalidClaims
    case revoked
    case expired
    case issuedInFuture

    public var description: String {
        switch self {
        case .invalidSignature: return "Invalid signature"
        case .invalidMembership: return "Invalid membership"
        case .invalidClaims: return "Invalid claims"
        case .revoked: return "Certificate is revoked"
        case .expired: return "Certificate not valid anymore."
        case .issuedInFuture: return "Issuing date lies in the future."
        }
    }
}
