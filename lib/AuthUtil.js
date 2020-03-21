/******************************************************************************
 * Copyright (c) 2020.  Peter Craftsmn                                        *
 * Written by Peter Craftsmn                                                  *
 * peter.craftsmn@gmail.com                                                   *
 ******************************************************************************/

/**
 * This class methods should be used to bring req.user object to looks as follows
 * some attributes may be missing
 * {
 *     req: {
 *         user: {
 *             username: "some username",
 *             password: "some password",
 *             id: "some id string",
 *             type: "some user type",
 *             salt: "some salt string",
 *             hash: "password and salt hash string",
 *             .
 *             .
 *             .
 *             storedUser: "user stored in database",
 *             token: {
 *                 header: "some token header",
 *                 payload: "some token payload"
 *             },
 *             webToken: "some web token string including signature string",
 *             webTokenSignature: "some signature string"
 *         }
 *     }
 * }
 *
 * Incoming webToken, username, password may be in the header or in the body.
 * These methods should extract them and attache to req.user object
 */

class AuthUtil {

    async parseWebTokenFromAuthorizationHeader( req ) {

    }

}

module.exports = AuthUtil;

