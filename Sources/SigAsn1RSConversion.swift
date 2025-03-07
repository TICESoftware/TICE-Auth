import Foundation

// Source: https://github.com/Kitura/BlueECC/blob/master/Sources/CryptorECC/ASN1.swift

/**
 * Copyright IBM Corporation 2019
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

enum ASN1 {

    indirect enum ASN1Element {
        case seq(elements: [ASN1Element])
        case integer(int: Int)
        case bytes(data: Data)
        case constructed(tag: Int, elem: ASN1Element)
        case unknown
    }

    static func toASN1Element(data: Data) -> (ASN1Element, Int) {
        guard data.count >= 2 else {
            // format error
            return (.unknown, data.count)
        }

        switch data[0] {
        case 0x30: // sequence
            let (length, lengthOfLength) = readLength(data: data.advanced(by: 1))
            var result: [ASN1Element] = []
            var subdata = data.advanced(by: 1 + lengthOfLength)
            var alreadyRead = 0

            while alreadyRead < length {
                let (e, l) = toASN1Element(data: subdata)
                result.append(e)
                subdata = subdata.count > l ? subdata.advanced(by: l) : Data()
                alreadyRead += l
            }
            return (.seq(elements: result), 1 + lengthOfLength + length)

        case 0x02: // integer
            let (length, lengthOfLength) = readLength(data: data.advanced(by: 1))
            if length < 8 {
                var result: Int = 0
                let subdata = data.advanced(by: 1 + lengthOfLength)
                // ignore negative case
                for i in 0..<length {
                    result = 256 * result + Int(subdata[i])
                }
                return (.integer(int: result), 1 + lengthOfLength + length)
            }
            // number is too large to fit in Int; return the bytes
            return (.bytes(data: data.subdata(in: (1 + lengthOfLength) ..< (1 + lengthOfLength + length))), 1 + lengthOfLength + length)

        case let s where (s & 0xe0) == 0xa0: // constructed
            let tag = Int(s & 0x1f)
            let (length, lengthOfLength) = readLength(data: data.advanced(by: 1))
            let subdata = data.advanced(by: 1 + lengthOfLength)
            let (e, _) = toASN1Element(data: subdata)
            return (.constructed(tag: tag, elem: e), 1 + lengthOfLength + length)

        default: // octet string
            let (length, lengthOfLength) = readLength(data: data.advanced(by: 1))
            return (.bytes(data: data.subdata(in: (1 + lengthOfLength) ..< (1 + lengthOfLength + length))), 1 + lengthOfLength + length)
        }
    }

    private static func readLength(data: Data) -> (Int, Int) {
        if data[0] & 0x80 == 0x00 { // short form
            return (Int(data[0]), 1)
        } else {
            let lenghOfLength = Int(data[0] & 0x7F)
            var result: Int = 0
            for i in 1..<(1 + lenghOfLength) {
                result = 256 * result + Int(data[i])
            }
            return (result, 1 + lenghOfLength)
        }
    }
}

// Source: https://github.com/Kitura/BlueECC/blob/master/Sources/CryptorECC/ECSignature.swift
// with some tiny modifications and fixes by TICE Software UG (haftungsbeschränkt)

//  Copyright © 2019 IBM. All rights reserved.
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

func rsSigToASN1(_ rs: Data) throws -> Data {
    let count = rs.count
    // swiftlint:disable:next empty_count
    guard count != 0 && count % 2 == 0 else {
        throw CertificateValidationError.invalidSignature
    }

    let r = Data(rs[..<(count / 2)])
    let s = Data(rs[(count / 2)...])
    
    guard r.count == s.count, r.count == 32 || r.count == 48 || r.count == 66 else {
        throw CertificateCreationError.tokenGenerationFailed
    }
    // Convert r,s signature to ASN1 for SecKeyVerifySignature
    var asnSignature = Data()
    // r value is first 32 bytes
    var rSig = r
    // Strip leading null bytes
    while rSig[0] == 0 {
        rSig = rSig.advanced(by: 1)
    }
    // If first bit is 1, add a 00 byte to mark it as positive for ASN1
    if rSig[0].leadingZeroBitCount == 0 {
        rSig = Data(count: 1) + rSig
    }
    // r value is last 32 bytes
    var sSig = s
    // Strip leading null bytes
    while sSig[0] == 0 {
        sSig = sSig.advanced(by: 1)
    }
    // If first bit is 1, add a 00 byte to mark it as positive for ASN1
    if sSig[0].leadingZeroBitCount == 0 {
        sSig = Data(count: 1) + sSig
    }
    // Count Byte lengths for ASN1 length bytes
    let rLengthByte = UInt8(rSig.count)
    let sLengthByte = UInt8(sSig.count)
    // total bytes is r + s + rLengthByte + sLengthByte byte + Integer marking bytes
    let tLengthByte = rLengthByte + sLengthByte + 4
    // 0x30 means sequence, 0x02 means Integer
    if tLengthByte > 127 {
        asnSignature.append(contentsOf: [0x30, 0x81, tLengthByte])
    } else {
        asnSignature.append(contentsOf: [0x30, tLengthByte])
    }
    asnSignature.append(contentsOf: [0x02, rLengthByte])
    asnSignature.append(rSig)
    asnSignature.append(contentsOf: [0x02, sLengthByte])
    asnSignature.append(sSig)
    return asnSignature
}

func asn1ToRSSig(asn1: Data) throws -> Data {
    
    let signatureLength: Int
    if asn1.count < 96 {
        signatureLength = 64
    } else if asn1.count < 132 {
        signatureLength = 96
    } else {
        signatureLength = 132
    }
    
    // Parse ASN into just r,s data as defined in:
    // https://tools.ietf.org/html/rfc7518#section-3.4
    let (asnSig, _) = ASN1.toASN1Element(data: asn1)
    guard case let ASN1.ASN1Element.seq(elements: seq) = asnSig,
        seq.count >= 2,
        case let ASN1.ASN1Element.bytes(data: rData) = seq[0],
        case let ASN1.ASN1Element.bytes(data: sData) = seq[1]
    else {
        throw CertificateCreationError.tokenGenerationFailed
    }
    // ASN adds 00 bytes in front of negative Int to mark it as positive.
    // These must be removed to make r,a a valid EC signature
    let trimmedRData: Data
    let trimmedSData: Data
    let rExtra = rData.count - signatureLength / 2
    if rExtra < 0 {
        trimmedRData = Data(count: -rExtra) + rData
    } else {
        trimmedRData = rData.dropFirst(rExtra)
    }
    let sExtra = sData.count - signatureLength / 2
    if sExtra < 0 {
        trimmedSData = Data(count: -sExtra) + sData
    } else {
        trimmedSData = sData.dropFirst(sExtra)
    }
    return trimmedRData + trimmedSData
}
