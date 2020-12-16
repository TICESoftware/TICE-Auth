//
//  Copyright © 2020 Anbion. All rights reserved.
//

import Foundation
import TICEModels
import Sodium

extension KeyExchange.PublicKey {
    var dataKey: TICEModels.PublicKey { Data(self) }
}

extension KeyExchange.KeyPair {
    var dataKeyPair: TICEModels.KeyPair {
        TICEModels.KeyPair(privateKey: Data(secretKey), publicKey: publicKey.dataKey)
    }
}

extension TICEModels.PublicKey {
    var keyExchangeKey: KeyExchange.PublicKey { Bytes(self) }
}

extension TICEModels.KeyPair {
    var keyExchangeKeyPair: KeyExchange.KeyPair {
        KeyExchange.KeyPair(publicKey: publicKey.keyExchangeKey, secretKey: Bytes(privateKey))
    }
}
