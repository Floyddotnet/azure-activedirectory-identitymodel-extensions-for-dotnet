// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.JsonWebTokens;

namespace System.IdentityModel.Tokens.Jwt
{
    /// <summary>
    /// Static class to convert a <see cref="JsonWebToken"/> to a <see cref="JwtSecurityToken"/>
    /// </summary>
    public static class JwtSecurityTokenConverter
    {
        /// <summary>
        /// Initializes a new instance of a <see cref="JwtSecurityToken"/> from a <see cref="JsonWebToken"/>
        /// </summary>
        /// <param name="token">A JSON Web Token to convert from.</param>
        /// <exception cref="ArgumentNullException"><paramref name="token"/> is null</exception>
        /// <exception cref="ArgumentException"><paramref name="token"/> doesn't have <see cref="JsonWebToken.EncodedToken"/> set.</exception>
        public static JwtSecurityToken Convert(JsonWebToken token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));

#if NET9_0_OR_GREATER
            if (token.InnerToken != null)
            {
                var jwtSecurityToken = new JwtSecurityToken(token.EncodedTokenMemory);
                jwtSecurityToken.InnerToken = new JwtSecurityToken(token.InnerToken.EncodedTokenMemory);
                return jwtSecurityToken;
            }
            else if (!token.EncodedTokenMemory.IsEmpty)
            {
                return new JwtSecurityToken(token.EncodedTokenMemory);
            }
#else
            if (token.InnerToken != null)
            {
                var jwtSecurityToken = new JwtSecurityToken(token.EncodedToken);
                jwtSecurityToken.InnerToken = new JwtSecurityToken(token.InnerToken.EncodedToken);
                return jwtSecurityToken;
            }
            else if (!string.IsNullOrEmpty(token.EncodedToken))
            {
                return new JwtSecurityToken(token.EncodedToken);
            }
#endif

            throw new ArgumentException("token.EncodedToken must be set");
        }
    }
}
