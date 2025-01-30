/*
 * Fledge S2OPCUA South service plugin
 *
 * Copyright (c) 2021-2025 Dianomic Systems
 *
 * Released under the Apache 2.0 Licence
 *
 * Author: Ashwini Kumar Pandey
 */
#ifndef PARSER_H
#define PARSER_H

#include <sstream>
#include <limits>

/**
 * @brief Parses a string representing an unsigned integer and stores the result in the provided variable.
 *
 * This function attempts to parse the input string `val` as an unsigned integer of type `T`.
 * If the parsing is successful and the parsed value does not exceed `maxLimit`, the result is stored
 * in the provided reference `result` and the function returns true. Otherwise, the function returns false.
 *
 * @tparam T The type of the result variable. Must be an unsigned integer type.
 * @param val The input string to be parsed.
 * @param result Reference to the variable where the parsed value will be stored if parsing is successful.
 * @param maxLimit The maximum allowable value for the parsed integer.
 * @return true if the parsing is successful and the parsed value is within the specified limit, false otherwise.
 */
template <typename T>
bool parseUnsignedInt(const char *val, T &result, T maxLimit)
{
    std::istringstream iss(val);
    unsigned long long parsedValue = 0;
    iss >> parsedValue;

    if (!iss.fail() && iss.eof() && parsedValue <= maxLimit)
    {
        result = static_cast<T>(parsedValue);
        return true;
    }
    return false;
}

/**
 * @brief Parses a string representing a signed integer and stores the result in the provided variable.
 *
 * This function attempts to parse the input string `val` as a signed integer of type `T`.
 * If the parsing is successful and the parsed value is within the range `[minLimit, maxLimit]`,
 * the result is stored in the provided reference `result` and the function returns true. Otherwise, the function returns false.
 *
 * @tparam T The type of the result variable. Must be a signed integer type.
 * @param val The input string to be parsed.
 * @param result Reference to the variable where the parsed value will be stored if parsing is successful.
 * @param minLimit The minimum allowable value for the parsed integer.
 * @param maxLimit The maximum allowable value for the parsed integer.
 * @return true if the parsing is successful and the parsed value is within the specified range, false otherwise.
 */
template <typename T>
bool parseSignedInt(const char *val, T &result, T minLimit, T maxLimit)
{
    std::istringstream iss(val);
    long long parsedValue = 0;
    iss >> parsedValue;

    if (!iss.fail() && iss.eof() && parsedValue >= minLimit && parsedValue <= maxLimit)
    {
        result = static_cast<T>(parsedValue);
        return true;
    }
    return false;
}

/**
 * @brief Parses a string representing a floating-point number and stores the result in the provided variable.
 *
 * This function attempts to parse the input string `val` as a floating-point number of type `T`.
 * If the parsing is successful, the result is stored in the provided reference `result` and the function returns true.
 * Otherwise, the function returns false.
 *
 * @tparam T The type of the result variable. Must be a floating-point type.
 * @param val The input string to be parsed.
 * @param result Reference to the variable where the parsed value will be stored if parsing is successful.
 * @return true if the parsing is successful, false otherwise.
 */
inline bool parseFloat(const char *val, float &result)
{
    std::istringstream iss(val);
    iss >> result;

    return !iss.fail() && iss.eof();
}

/**
 * @brief Parses a string representing a double-precision floating-point number and stores the result in the provided variable.
 *
 * This function attempts to parse the input string `val` as a double-precision floating-point number.
 * If the parsing is successful, the result is stored in the provided reference `result` and the function returns true.
 * Otherwise, the function returns false.
 *
 * @param val The input string to be parsed.
 * @param result Reference to the variable where the parsed value will be stored if parsing is successful.
 * @return true if the parsing is successful, false otherwise.
 */
inline bool parseDouble(const char *val, double &result)
{
    std::istringstream iss(val);
    iss >> result;

    return !iss.fail() && iss.eof();
}

#endif // PARSER_H
