/*
 * Utils functions
 *
 */

/**
 * Break string str each maxLen symbols
 * @param str
 * @param maxLen
 * @returns {string}
 */
module.exports.linebrk = function (str, maxLen) {
    var res = "";
    var i = 0;
    while (i + maxLen < str.length) {
        res += str.substring(i, i + maxLen) + "\n";
        i += maxLen;
    }
    return res + str.substring(i, str.length);
};