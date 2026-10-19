/*
 * Copyright (c) 2025, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */

using DuckDB.NET.Data;
using gov.llnl.wintap.helpers;
using System.Text;

/// <summary>
/// Provides centralized management of DuckDB connections and views for querying Wintap telemetry data from MCP.
/// </summary>
/// <remarks>
/// <para>
/// The DuckDBManager creates an in-memory DuckDB instance that provides SQL views over Parquet files
/// containing Wintap telemetry data. This enables efficient querying of process, network, file, registry,
/// and other system activity data using standard SQL.
/// </para>
/// 
/// <para><strong>Architecture:</strong></para>
/// <list type="bullet">
/// <item><description>Uses a singleton in-memory DuckDB connection for the application lifetime</description></item>
/// <item><description>Automatically creates SQL views that reference Parquet files on disk</description></item>
/// <item><description>Supports cross-platform paths (Windows: %ProgramData%, Linux: /var/log/lintap)</description></item>
/// <item><description>Provides cancellation support for long-running queries</description></item>
/// </list>
/// 
/// <para><strong>Available Views:</strong></para>
/// <list type="bullet">
/// <item><description><c>Wintap_Process</c> - Process lifecycle events (start, stop)</description></item>
/// <item><description><c>Wintap_Tcp</c> - TCP connection events</description></item>
/// <item><description><c>Wintap_Udp</c> - UDP connection events</description></item>
/// <item><description><c>Wintap_Registry</c> - Registry access events</description></item>
/// <item><description><c>Wintap_File</c> - File system activity</description></item>
/// <item><description><c>Wintap_WMI</c> - WMI query events</description></item>
/// <item><description><c>Wintap_APICalls</c> - Windows API call monitoring</description></item>
/// <item><description><c>Wintap_Memory</c> - Memory mapping events</description></item>
/// <item><description><c>Wintap_ImageLoad</c> - DLL/binary load events</description></item>
/// <item><description><c>Wintap_FocusChange</c> - Window focus change events</description></item>
/// <item><description><c>Wintap_CpuTrigger</c> - CPU threshold trigger events</description></item>
/// </list>
/// 
/// <para><strong>Cross-Platform Paths:</strong></para>
/// <list type="bullet">
/// <item><description>Windows: <c>C:\ProgramData\Wintap\data\raw_sensor\</c></description></item>
/// <item><description>Unix: <c>/var/log/lintap/data/raw_sensor/</c></description></item>
/// </list>
/// 
/// <para><strong>Usage Example:</strong></para>
/// <code>
/// // Initialize the manager (call once at application startup)
/// DuckDBManager.Initialize();
/// 
/// // Execute SQL query
/// string query = "SELECT * FROM Wintap_Process WHERE ProcessName = 'chrome.exe' LIMIT 10";
/// string results = DuckDBManager.ExecuteSQL(query, cancellationToken);
/// </code>
/// 
/// <para><strong>Thread Safety:</strong></para>
/// <para>
/// This class uses a singleton pattern with lazy initialization. The Initialize() method should be called
/// once during application startup. The ExecuteSQL() method is thread-safe for concurrent read operations,
/// as DuckDB supports multiple concurrent readers on the same connection.
/// </para>
/// 
/// 
/// <para><strong>Error Handling:</strong></para>
/// <para>
/// The CreateOrReplaceProcessViews() method silently catches exceptions when creating individual views,
/// allowing the application to continue even if some telemetry types are unavailable. ExecuteSQL()
/// returns error messages as strings for display to users.
/// </para>
/// </remarks>
public static class DuckDBManager
{
    private static DuckDBConnection _connection;

    public static void Initialize()
    {
        if (_connection == null)
        {
            _connection = new DuckDBConnection("Data Source=:memory:");
            _connection.Open();
            CreateOrReplaceProcessViews();
        }
    }

    private static void CreateOrReplaceProcessViews()
    {

        string dataRoot = Environment.GetEnvironmentVariable("WINTAP_DATA_ROOT")
            ?? (OperatingSystem.IsWindows()
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Wintap", "data")
                : Path.Combine("/var/log/lintap", "data"));
        string parquetDir = Path.Combine(dataRoot, "raw_sensor");

        string processParquet = Path.Combine(parquetDir, "raw_process", "**", "*.parquet");
        string tcpParquet = Path.Combine(parquetDir, "raw_tcp_process_conn_incr", "**", "*.parquet");
        string udpParquet = Path.Combine(parquetDir, "raw_udp_process_conn_incr", "**", "*.parquet");
        string registryParquet = Path.Combine(parquetDir, "raw_registry", "**", "*.parquet");
        string fileParquet = Path.Combine(parquetDir, "raw_file", "**", "*.parquet");
        string wmiParquet = Path.Combine(parquetDir, "raw_wmi", "**", "*.parquet");
        string apiParquet = Path.Combine(parquetDir, "raw_apicall", "**", "*.parquet");
        string memoryParquet = Path.Combine(parquetDir, "raw_memorymap", "**", "*.parquet");
        string ilParquet = Path.Combine(parquetDir, "raw_imageload", "**", "*.parquet");
        string fcParquet = Path.Combine(parquetDir, "raw_focuschange", "**", "*.parquet");
        string cpuParquet = Path.Combine(parquetDir, "raw_cputrigger", "**", "*.parquet");
        string eventlogParquet = Path.Combine(parquetDir, "raw_eventlogevent", "**", "*.parquet");

        string parquetGlobSql = processParquet.Replace(@"\", @"\\");
        string sqlProcess = $@"
            CREATE OR REPLACE VIEW Wintap_Process AS
            SELECT * FROM read_parquet('{parquetGlobSql}');
        ";

        string parquetPath = tcpParquet.Replace(@"\", @"\\");
        string sqlTcp = $@"
            CREATE OR REPLACE VIEW Wintap_Tcp AS
            SELECT * FROM read_parquet('{parquetPath}');
        ";

        parquetPath = udpParquet.Replace(@"\", @"\\");
        string sqlUdp = $@"
            CREATE OR REPLACE VIEW Wintap_Udp AS
            SELECT * FROM read_parquet('{parquetPath}');
        ";

        parquetPath = registryParquet.Replace(@"\", @"\\");
        string sqlRegistry = $@"
            CREATE OR REPLACE VIEW Wintap_Registry AS
            SELECT * FROM read_parquet('{parquetPath}');
        ";

        parquetPath = fileParquet.Replace(@"\", @"\\");
        string sqlFile = $@"
            CREATE OR REPLACE VIEW Wintap_File AS
            SELECT * FROM read_parquet('{parquetPath}');
        ";

        parquetPath = wmiParquet.Replace(@"\", @"\\");
        string sqlWmi = $@"
            CREATE OR REPLACE VIEW Wintap_WMI AS
            SELECT * FROM read_parquet('{parquetPath}');
        ";

        parquetPath = apiParquet.Replace(@"\", @"\\");
        string sqlApi = $@"
            CREATE OR REPLACE VIEW Wintap_APICalls AS
            SELECT * FROM read_parquet('{parquetPath}');
        ";

        parquetPath = memoryParquet.Replace(@"\", @"\\");
        string sqlMemory = $@"
            CREATE OR REPLACE VIEW Wintap_Memory AS
            SELECT * FROM read_parquet('{parquetPath}');
        ";

        parquetPath = ilParquet.Replace(@"\", @"\\");
        string sqlIl = $@"
            CREATE OR REPLACE VIEW Wintap_ImageLoad AS
            SELECT * FROM read_parquet('{parquetPath}');
        ";

        parquetPath = fcParquet.Replace(@"\", @"\\");
        string sqlFc = $@"
            CREATE OR REPLACE VIEW Wintap_FocusChange AS
            SELECT * FROM read_parquet('{parquetPath}');
        ";

        parquetPath = cpuParquet.Replace(@"\", @"\\");
        string sqlCpu = $@"
            CREATE OR REPLACE VIEW Wintap_CpuTrigger AS
            SELECT * FROM read_parquet('{parquetPath}');
        ";

        parquetPath = eventlogParquet.Replace(@"\", @"\\");
        string sqlEventlog = $@"
            CREATE OR REPLACE VIEW Wintap_Eventlog AS
            SELECT * FROM read_parquet('{parquetPath}');
        ";

        using (var command = _connection.CreateCommand())
        {
            try
            {
                command.CommandText = sqlProcess;
                command.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                // to do:  log the error
            }

            try
            {
                command.CommandText = sqlTcp;
                command.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                // to do:  log the error
            }

            try
            {
                command.CommandText = sqlFile;
                command.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                // to do:  log the error
            }


            try
            {
                command.CommandText = sqlRegistry;
                command.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                // to do:  log the error
            }

            try
            {
                command.CommandText = sqlIl;
                command.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                // to do:  log the error
            }


            try
            {
                command.CommandText = sqlApi;
                command.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                // to do:  log the error
            }

            try
            {
                command.CommandText = sqlWmi;
                command.ExecuteNonQuery();
            }
            catch (Exception ex)
            {

            }

            try
            {
                command.CommandText = sqlMemory;
                command.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                // to do:  log the error
            }

            try
            {
                command.CommandText = sqlFc;
                command.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                // to do:  log the error
            }

            try
            {
                command.CommandText = sqlCpu;
                command.ExecuteNonQuery();
            }
            catch (Exception ex)
            {
                // to do:  log the error
            }

            try
            {
                command.CommandText = sqlEventlog;
                command.ExecuteNonQuery();
            }
            catch (Exception ex) { }
        }
    }

    public static string ExecuteSQL(string sqlCmd, CancellationToken cancellationToken)
    {
        Logit.Instance.Append($"AI SQL: {sqlCmd}", LogVerboseLevel.Normal);
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = sqlCmd;

            if (cancellationToken.IsCancellationRequested)
                throw new OperationCanceledException();

            try
            {
                using (var reader = command.ExecuteReader())
                {
                    var sb = new StringBuilder();

                    // Write column headers
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        if (i > 0) sb.Append('\t');
                        sb.Append(reader.GetName(i));
                    }
                    sb.AppendLine();

                    // Write rows
                    while (reader.Read())
                    {
                        if (cancellationToken.IsCancellationRequested)
                            throw new OperationCanceledException();

                        for (int i = 0; i < reader.FieldCount; i++)
                        {
                            if (i > 0) sb.Append('\t');
                            sb.Append(reader.IsDBNull(i) ? "NULL" : reader.GetValue(i).ToString());
                        }
                        sb.AppendLine();
                    }

                    return sb.ToString();
                }
            }
            catch (DuckDBException ex) when (ex.Message.Contains("no results"))
            {
                int affected = command.ExecuteNonQuery();
                return $"Command executed successfully. Rows affected: {affected}";
            }
            catch (Exception ex)
            {
                return $"Error: {ex.Message}";
            }
        }
    }
}
