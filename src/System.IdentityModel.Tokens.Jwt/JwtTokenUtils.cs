// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace System.IdentityModel.Tokens.Jwt
{
    internal class JwtTokenUtils
    {

#if NET9_0_OR_GREATER
        internal static ReadOnlyMemory<char>[] SplitToken(string jwtEncodedString)
        {
            return SplitToken(jwtEncodedString.AsMemory());
        }
#else
        internal static string[] SplitToken(string jwtEncodedString)
        {
            return jwtEncodedString.Split('.');
        }
#endif

#if NET9_0_OR_GREATER
        internal static ReadOnlyMemory<char>[] SplitToken(ReadOnlyMemory<char> jwtEncodedString)
        {
            if (jwtEncodedString.IsEmpty)
                throw LogHelper.LogArgumentException<ArgumentException>(nameof(jwtEncodedString), $"{nameof(jwtEncodedString)} is empty.");

            ReadOnlySpan<char> tokenSpan = jwtEncodedString.Span;

            Span<int> dotIndexes = stackalloc int[JwtConstants.MaxJwtSegmentCount];

            int dotCount = 0;
            for (int i = 0; i < tokenSpan.Length && dotCount < dotIndexes.Length; i++)
            {
                if (tokenSpan[i] == '.')
                {
                    dotIndexes[dotCount++] = i;
                }
            }

            int segmentCount = dotCount + 1;
            if (segmentCount == JwtConstants.JwsSegmentCount)
            {
                if (!JwtTokenUtilities.RegexJws.IsMatch(tokenSpan))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenMalformedException(LogMessages.IDX12739));
            }
            else if (segmentCount == JwtConstants.JweSegmentCount)
            {
                if (!JwtTokenUtilities.RegexJwe.IsMatch(tokenSpan))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenMalformedException(LogMessages.IDX12740));
            }
            else
                throw LogHelper.LogExceptionMessage(new SecurityTokenMalformedException(LogMessages.IDX12741));

            // Slice segments
            ReadOnlyMemory<char>[] memorySegments = new ReadOnlyMemory<char>[segmentCount];
            int start = 0;
            for (int i = 0; i < dotCount; i++)
            {
                memorySegments[i] = jwtEncodedString.Slice(start, dotIndexes[i] - start);
                start = dotIndexes[i] + 1;
            }

            memorySegments[dotCount] = jwtEncodedString[start..];
            return memorySegments;
        }
#endif
    }
}
