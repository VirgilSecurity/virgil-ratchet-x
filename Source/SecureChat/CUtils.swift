//
//  CUtils.swift
//  VirgilSDKRatchet
//
//  Created by Oleksandr Deundiak on 10/17/18.
//  Copyright © 2018 Oleksandr Deundiak. All rights reserved.
//

import Foundation

class CUtils {
    internal static func bindForRead(data: Data?) -> OpaquePointer? {
        guard let data = data else {
            return nil
        }
        
        return data.withUnsafeBytes {
            return OpaquePointer($0)
        }
    }
}
