//
// Copyright (C) 2015-2019 Virgil Security Inc.
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
import VirgilSDK

/// Class for saving Sessions and One-time keys to the filesystem
/// NOTE: This class is not thread-safe
internal class FileSystem {
    private let fileManager = FileManager()
    private let userIdentifier: String
    private let pathComponents: [String]

    internal init(userIdentifier: String, pathComponents: [String]) {
        self.userIdentifier = userIdentifier
        self.pathComponents = pathComponents
    }

    private func createRatchetSuppDir() throws -> URL {
        var dirUrl = try self.fileManager.url(for: .applicationSupportDirectory,
                                              in: .userDomainMask,
                                              appropriateFor: nil,
                                              create: true)

        dirUrl.appendPathComponent("VIRGIL-RATCHET")
        dirUrl.appendPathComponent("\(self.userIdentifier)")

        do {
            try self.fileManager.createDirectory(at: dirUrl, withIntermediateDirectories: true, attributes: nil)
            Log.debug("Created \(dirUrl.absoluteString) folder")

            var values = URLResourceValues()
            values.isExcludedFromBackup = true

            try dirUrl.setResourceValues(values)
        }
        catch {
            Log.error("Error creating \(dirUrl.absoluteString) folder")
            throw error
        }

        return dirUrl
    }

    private func writeFile(url: URL, data: Data) throws {
    #if os(OSX)
        let options: Data.WritingOptions = [.atomic]
    #else
        let options: Data.WritingOptions = [
            .completeFileProtection /* Is accessing in background needed? */,
            .atomic
        ]
    #endif

        try data.write(to: url, options: options)
    }

    private func readFile(url: URL) -> Data {
        return (try? Data(contentsOf: url)) ?? Data()
    }

    private func getFullUrl(name: String?, subdir: String?) throws -> URL {
        var url = try self.createRatchetSuppDir()

        self.pathComponents.forEach {
            url.appendPathComponent($0)
        }

        if let subdir = subdir {
            url.appendPathComponent(subdir)
        }

        try self.fileManager.createDirectory(at: url, withIntermediateDirectories: true, attributes: nil)

        if let name = name {
            url.appendPathComponent(name)
        }

        return url
    }
}

internal extension FileSystem {
    func write(data: Data, name: String, subdir: String? = nil) throws {
        let url = try self.getFullUrl(name: name, subdir: subdir)

        try self.writeFile(url: url, data: data)
    }

    func read(name: String, subdir: String? = nil) throws -> Data {
        let url = try self.getFullUrl(name: name, subdir: subdir)

        return self.readFile(url: url)
    }

    func delete(name: String, subdir: String? = nil) throws {
        let url = try self.getFullUrl(name: name, subdir: subdir)

        try self.fileManager.removeItem(at: url)
    }

    func delete(subdir: String? = nil) throws {
        let url = try self.getFullUrl(name: nil, subdir: subdir)

        try self.fileManager.removeItem(at: url)
    }
}
