//
//  Copyright © 2021 Anbion. All rights reserved.
//

import Foundation
import JWTKit

struct KeyClaims: Claims {
    let iss: UserId
    let iat: IssuedAtClaim
    let exp: ExpirationClaim
    let pubKey: PublicKey
    
    init(iss: UserId, iat: Date, exp: Date, publicKey: PublicKey) {
        self.iss = iss
        self.iat = IssuedAtClaim(value: iat)
        self.exp = ExpirationClaim(value: exp)
        self.pubKey = publicKey
    }
}
