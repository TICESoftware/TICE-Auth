//
//  Copyright © 2020 Anbion. All rights reserved.
//

import Foundation

// MARK: TICEModels

public typealias Certificate = String
public typealias GroupId = UUID
public typealias UserId = UUID
public typealias PrivateKey = Data
public typealias PublicKey = Data

public struct Membership: Codable, Equatable {
    public let userId: UserId
    public let groupId: GroupId
    public let publicSigningKey: PublicKey
    public let admin: Bool

    public var selfSignedMembershipCertificate: Certificate?
    public var serverSignedMembershipCertificate: Certificate
    public var adminSignedMembershipCertificate: Certificate?

    public init(userId: UserId, publicSigningKey: PublicKey, groupId: GroupId, admin: Bool, selfSignedMembershipCertificate: Certificate? = nil, serverSignedMembershipCertificate: Certificate, adminSignedMembershipCertificate: Certificate? = nil) {
        self.userId = userId
        self.publicSigningKey = publicSigningKey
        self.groupId = groupId
        self.admin = admin
        self.selfSignedMembershipCertificate = selfSignedMembershipCertificate
        self.serverSignedMembershipCertificate = serverSignedMembershipCertificate
        self.adminSignedMembershipCertificate = adminSignedMembershipCertificate
    }
}

// MARK: TICECrypto

public typealias JWTId = UUID
