# -------------------------------------------------------------------------------
# Name:         utils
# Purpose:      Various utils required for verifying NTLMv2 hashes
#
# Author:      Oliver Sealey <github.com/opdsealey>
#
# Created:     22/02/2020
# Copyright:   (c) Oliver Sealey 2020
# Licence:     GPL
# -------------------------------------------------------------------------------
using System;

namespace NetNTLMv2Checker
{
    class utils
    {
        // https://stackoverflow.com/questions/311165/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-and-vice-versa
        public static string ByteArrayToString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }

        // https://stackoverflow.com/questions/311165/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-and-vice-versa
        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}
