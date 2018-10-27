//
//  CUtils.swift
//  VirgilSDKRatchet
//
//  Created by Oleksandr Deundiak on 10/17/18.
//  Copyright © 2018 Oleksandr Deundiak. All rights reserved.
//

import Foundation
import VirgilCryptoApiImpl
import VSCCommon

internal class CUtils {
    internal static func computeKeyId(publicKey: Data) -> Data {
        return VirgilCrypto().computeHash(for: publicKey, using: .SHA512).subdata(in: 0..<8)
    }
    
    internal static func extractRawPublicKey(_ key: Data) -> Data {
        return Data(key.subdata(in: key.count - 64..<key.count - 32).reversed())
    }
    
    internal static func extractRawPrivateKey(_ key: Data) -> Data {
        return Data(key.subdata(in: 7..<39).reversed())
    }
    
    internal static func copy(data: Data, buffer: OpaquePointer) throws {
        guard data.copyBytes(to: UnsafeMutableBufferPointer(start: vsc_buffer_ptr(buffer), count: vsc_buffer_capacity(buffer))) == data.count else {
            throw NSError()
        }
        vsc_buffer_reserve(buffer, data.count)
    }
    
    internal static func bindForRead(data: Data) -> vsc_data_t {
        return data.withUnsafeBytes({ (pointer: UnsafePointer<UInt8>) in
            return vsc_data(pointer, data.count)
        })
    }
    
    internal static func bindForWrite(capacity: Int, buffer: OpaquePointer) -> Data {
        var data = Data(capacity: capacity)
        data.count = capacity
        data.withUnsafeMutableBytes({ (pointer: UnsafeMutablePointer<UInt8>) in
            vsc_buffer_use(buffer, pointer, capacity)
        })
        
        return data
    }
}
