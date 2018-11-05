//
// Copyright (C) 2015-2018 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
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
