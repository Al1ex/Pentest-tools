# -------------------------------------------------------------------------------
# Name:         ntlm
# Purpose:      Main wrapper for checking NTLMv2 Type 3 hashes
#
# Author:      Oliver Sealey <github.com/opdsealey>
#
# Created:     22/02/2020
# Copyright:   (c) Oliver Sealey 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace NetNTLMv2Checker
{
    class ntlm
    {
        public static byte[] getNTLMv2Response(string target, string user, string password, byte[] server_challenege, byte[] blob)
        {
            /*
             * Creates the NTLMv2 Response see in the Type 3 NTLM Message
             */
            byte[] ntlmv2Response = new byte[16];
            byte[] ntlmv2Hash = new byte[16];
            byte[] targetInfomration = new byte[server_challenege.Length + blob.Length];

            System.Buffer.BlockCopy(server_challenege, 0, targetInfomration, 0, server_challenege.Length);
            System.Buffer.BlockCopy(blob, 0, targetInfomration, server_challenege.Length, blob.Length);

            ntlmv2Hash = ntlm.getNtlmv2Hash(target, user, password);
            HMACMD5 hmac = new HMACMD5(ntlmv2Hash);

            ntlmv2Response = hmac.ComputeHash(targetInfomration);

            return ntlmv2Response;



        }
        public static byte[] getNtlmv2Hash(string target, string user, string password)
        {
            /*
             * Creates the NTLMv2 hash
             * This is created by concatinating the Unicode version of uppercase username and target/domain and HMAC_MD5 these using the NTLM as the key
             */
            byte[] ntlmHash = new byte[16];
            byte[] ntlmv2Hash = new byte[16];

            string targetInfomration = user.ToUpper() + target.ToUpper();
            UnicodeEncoding unicode = new UnicodeEncoding();
            ntlmHash = ntlm.getNtlmHash(password);

            HMACMD5 hmac = new HMACMD5(ntlmHash);

            ntlmv2Hash = hmac.ComputeHash(unicode.GetBytes(targetInfomration));

            return ntlmv2Hash;

        }

        public static byte[] getNtlmHash(string password)
        {
            /*
             * Creates the NTLM hash, this is the MD4 of the the password
             */
             
            byte[] ntlmHash = new byte[16];
            UnicodeEncoding unicode = new UnicodeEncoding();
            MD4 md4 = new MD4();
            ntlmHash = md4.GetByteHashFromBytes(unicode.GetBytes(password));
            return ntlmHash;
        }

        
    }
}
