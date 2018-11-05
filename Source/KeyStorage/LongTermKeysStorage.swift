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

@objc(VSRLongTermKey) public final class LongTermKey: NSObject {
    @objc public let identifier: Data
    @objc public let key: Data
    @objc public let creationDate: Date
    @objc public let outdatedFrom: Date?
    
    @objc public init(identifier: Data, key: Data, creationDate: Date, outdatedFrom: Date?) {
        self.identifier = identifier
        self.key = key
        self.creationDate = creationDate
        self.outdatedFrom = outdatedFrom
        
        super.init()
    }
}

@objc(VSRLongTermKeysStorage) public protocol LongTermKeysStorage: class {
    @objc func storeKey(_ key: Data, withId id: Data) throws -> LongTermKey
    @objc func retrieveKey(withId id: Data) throws -> LongTermKey
    @objc func deleteKey(withId id: Data) throws
    @objc func retrieveAllKeys() throws -> [LongTermKey]
    @objc func markKeyOutdated(startingFrom date: Date, keyId: Data) throws
}
