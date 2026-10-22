using gov.llnl.wintap.collect.models;

using System;
using System.Text.RegularExpressions;

namespace gov.llnl.wintap.core.infrastructure.helpers
{
    /// <summary>
    /// Simple helper for formatting enum values as strings for the UI
    /// </summary>
    public static class EnumFormatter
    {
        /// <summary>
        /// Formats enum values to their string representation for display in the UI
        /// </summary>
        /// <param name="enumType">Type of enum (MessageType or ActivityType)</param>
        /// <param name="value">The enum value</param>
        /// <returns>String representation</returns>
        public static string FormatEnumForDisplay(string enumType, object value)
        {
            if (value == null) return "null";

            // If it's already a string, return it
            if (value is string) return value.ToString();

            // Try to parse as int
            if (int.TryParse(value.ToString(), out int enumValue))
            {
                if (enumType.Equals("MessageType", StringComparison.OrdinalIgnoreCase))
                {
                    if (Enum.IsDefined(typeof(WintapMessage.MessageTypeEnum), enumValue))
                    {
                        return ((WintapMessage.MessageTypeEnum)enumValue).ToString();
                    }
                }
                else if (enumType.Equals("ActivityType", StringComparison.OrdinalIgnoreCase))
                {
                    if (Enum.IsDefined(typeof(WintapMessage.ActivityTypeEnum), enumValue))
                    {
                        return ((WintapMessage.ActivityTypeEnum)enumValue).ToString();
                    }
                }
            }

            // Default to original value
            return value.ToString();
        }

        public static string FormatQueryForCompile(string query)
        {
            if (string.IsNullOrEmpty(query))
                return query;

            try
            {
                // Handle MessageType string literals
                var messageTypeRegex = new Regex(@"MessageType\s*=\s*['""]([^'""]+)['""]");
                var matches = messageTypeRegex.Matches(query);

                if (matches.Count > 0)
                {
                    foreach (Match match in matches)
                    {
                        var typeString = match.Groups[1].Value;

                        bool msgTypeSupported = false;
                        foreach (var enumVal in Enum.GetValues(typeof(WintapMessage.MessageTypeEnum)))
                        {
                            if (typeString.ToUpper() == enumVal.ToString().ToUpper())
                            {
                                var replacement = $"CAST(MessageType, string) = '{typeString}'";
                                query = query.Replace(match.Value, replacement);
                                msgTypeSupported = true;
                            }
                        }
                        if (!msgTypeSupported)
                        {
                            throw new Exception($"Unsupported MessageType: {typeString}");
                        }

                    }
                }

                // Similar processing for ActivityType
                var activityTypeRegex = new Regex(@"ActivityType\s*=\s*['""]([^'""]+)['""]");
                matches = activityTypeRegex.Matches(query);

                if (matches.Count > 0)
                {
                    foreach (Match match in matches)
                    {
                        var typeString = match.Groups[1].Value;
                        if (Enum.TryParse<WintapMessage.ActivityTypeEnum>(typeString, true, out var enumValue))
                        {
                            // Replace with enum value or CAST function
                            var replacement = $"CAST(ActivityType, string) = '{typeString}'";
                            query = query.Replace(match.Value, replacement);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Log error but return original query
                WintapLogger.Log.Append($"Error formatting query: {ex.Message}", LogLevel.Debug);
                return query;
            }

            return query;
        }
    }
}