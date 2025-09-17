using System;
using System.Collections.Generic;
using System.IO.Ports;
using System.Linq;
using System.Text;
using System.Globalization;

//
// CashHealth.exe — “termómetro” de enlace con la validadora ITL
// Objetivo: confirmar puerto, handshake eSSP y parámetros básicos (sin mover dinero).
// Salida: JSON por stdout; trazas detalladas (TX/RX HEX) por stderr (diag.log).
//
class Program
{
    static int Main(string[] args)
    {
        // Parámetros de entrada
        // - por defecto COM7 y (en modo "simple") escaneo de dirección 0..3
        // - --addr X fuerza una dirección concreta
        // - --all agrega salida de varios dispositivos (0 y 16 por defecto; con --scan, 0..31)
        string port = "COM7";
        int? fixedAddr = null;
        bool aggregate = false;
        bool wideScan = false;

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--port" && i + 1 < args.Length) port = args[++i];
            else if (args[i] == "--addr" && i + 1 < args.Length) fixedAddr = int.Parse(args[++i]);
            else if (args[i] == "--all") aggregate = true;
            else if (args[i] == "--scan") wideScan = true; // solo tiene efecto con --all
        }

        try
        {
            // 1) Abrir puerto serie con los parámetros del dispositivo: 9600, 8-N-2
            using var sp = new SerialPort(port, 9600, Parity.None, 8, StopBits.Two)
            {
                Handshake = Handshake.None,
                ReadTimeout = 3000,   // margen generoso en el primer enlace
                WriteTimeout = 1000,
                DtrEnable = true,     // DTR/RTS activados: FTDI suele ir bien así
                RtsEnable = true
            };
            sp.Open();
            Log($"Opened {port} -> IsOpen={sp.IsOpen}");
            Log("Settings: 9600 8-N-2, Handshake=None, DTR/RTS=On, ReadTimeout=3000ms");

            if (!aggregate)
            {
                // ===== MODO SIMPLE (un solo dispositivo, como ya teníamos) =====
                // 2) SYNC robusto: escanear addr 0..3 y probar secuencia 0/1 (por si host/dispositivo están desalineados)
                var addrList = fixedAddr.HasValue ? new int[] { fixedAddr.Value } : new int[] { 0, 1, 2, 3 };
                SspWire ssp = null!;
                int detectedAddr = -1;
                byte usedSeqStart = 0;
                int attempts = 0;

                foreach (var addr in addrList)
                {
                    for (byte seqStart = 0; seqStart <= 1; seqStart++)
                    {
                        attempts++;
                        Log($"SYNC probe -> addr={addr}, seqStart={seqStart}");
                        ssp = new SspWire(sp, (byte)addr, seqStart, Log);

                        // SYNC (0x11) — si responde F0 = OK, tenemos enlace eSSP real
                        var (ok, statusHex) = ssp.SendSimple(new byte[] { 0x11 });
                        if (ok)
                        {
                            detectedAddr = addr;
                            usedSeqStart = seqStart;
                            Log($"SYNC OK at addr={addr}, seqStart={seqStart}, status={statusHex}");
                            goto SYNC_DONE_SINGLE;
                        }
                        else
                        {
                            Log($"No SYNC response/OK at addr={addr}, seqStart={seqStart}, status={statusHex}");
                        }
                    }
                }
            SYNC_DONE_SINGLE:
                if (detectedAddr < 0)
                {
                    // No hubo respuesta válida a SYNC en ningún intento
                    Console.WriteLine($"{{\"status\":\"ERROR\",\"step\":\"SYNC_SCAN_FAILED\",\"attempts\":{attempts}}}");
                    return 2;
                }

                // 3) Fijar versión de protocolo (HostProtocolVersion: 0x06)
                // Intentamos v8; si no acepta, bajamos a v6 (compatibilidad)
                Log("HostProtocolVersion -> 8...");
                var protoTry = ssp.SendSimple(new byte[] { 0x06, 0x08 });
                int protocolAccepted = -1;
                if (protoTry.ok)
                {
                    protocolAccepted = 8;
                    Log("HostProtocolVersion accepted: v8");
                }
                else
                {
                    Log("HostProtocolVersion 8 failed. Trying 6...");
                    var fallback = ssp.SendSimple(new byte[] { 0x06, 0x06 });
                    if (fallback.ok)
                    {
                        protocolAccepted = 6;
                        Log("HostProtocolVersion accepted: v6");
                    }
                }
                if (protocolAccepted < 0)
                {
                    Console.WriteLine("{\"status\":\"ERROR\",\"step\":\"HOST_PROTOCOL_VERSION\"}");
                    return 3;
                }

                // 4) SetupRequest (0x05) — lectura “segura”: dataset, nº de canales y otros
                var dev = ReadDeviceSetup(ssp, protocolAccepted, detectedAddr, port);
                if (!dev.ok)
                {
                    Console.WriteLine("{\"status\":\"ERROR\",\"step\":\"SETUP\"}");
                    return 4;
                }

                Console.WriteLine(dev.json);
                return 0;
            }
            else
            {
                // ===== MODO AGREGADO (--all) =====
                // Por defecto probamos direcciones típicas 0 (billetes) y 16 (monedas)
                // Con --scan, hacemos descubrimiento 0..31 (más lento).
                var addrs = wideScan ? Enumerable.Range(0, 32) : new int[] { 0, 16 };

                var devicesJson = new List<string>();
                foreach (var addr in addrs)
                {
                    // Para cada dirección probamos SYNC con seqStart 0 y 1
                    SspWire sspForAddr = null!;
                    bool found = false;
                    for (byte seqStart = 0; seqStart <= 1; seqStart++)
                    {
                        Log($"[ALL] SYNC probe -> addr={addr}, seqStart={seqStart}");
                        sspForAddr = new SspWire(sp, (byte)addr, seqStart, Log);
                        var (ok, _) = sspForAddr.SendSimple(new byte[] { 0x11 });
                        if (ok) { found = true; break; }
                    }
                    if (!found) continue; // no hay dispositivo en esta dirección

                    // HostProtocolVersion (v8 → v6)
                    int proto = -1;
                    var hpv8 = sspForAddr.SendSimple(new byte[] { 0x06, 0x08 });
                    if (hpv8.ok) proto = 8;
                    else
                    {
                        var hpv6 = sspForAddr.SendSimple(new byte[] { 0x06, 0x06 });
                        if (hpv6.ok) proto = 6;
                    }
                    if (proto < 0) continue;

                    // Setup y JSON del dispositivo
                    var dev = ReadDeviceSetup(sspForAddr, proto, addr, port);
                    if (dev.ok) devicesJson.Add(dev.json);
                }

                if (devicesJson.Count == 0)
                {
                    Console.WriteLine("{\"status\":\"ERROR\",\"step\":\"ALL_NO_DEVICES\"}");
                    return 5;
                }

                var sb = new StringBuilder();
                sb.Append("{\"status\":\"OK\"");
                sb.Append($",\"port\":{J(port)}");
                sb.Append(",\"baud\":9600");
                sb.Append(",\"devices\":[");
                for (int i = 0; i < devicesJson.Count; i++)
                {
                    if (i > 0) sb.Append(",");
                    sb.Append(devicesJson[i]);
                }
                sb.Append("]}");
                Console.WriteLine(sb.ToString());
                return 0;
            }
        }
        catch (Exception ex)
        {
            // Errores “duros” (puerto inaccesible, etc.)
            Error(ex.Message);
            Console.WriteLine("{\"status\":\"ERROR\",\"error\":\"" + ex.Message.Replace("\"", "\\\"") + "\"}");
            return 1;
        }
    }

    // ---------- lectura de Setup y construcción de JSON de un dispositivo ----------
    private static (bool ok, string json) ReadDeviceSetup(SspWire ssp, int protocolAccepted, int addr, string port)
    {
        Log("SetupRequest...");
        var setup = ssp.SendWithData(new byte[] { 0x05 });
        if (!setup.ok) return (false, "");

        Log($"SETUP payload (HEX): {ToHex(setup.data)}");

        // Detección de tipo de dispositivo por unitType (byte 0 del payload)
        byte unitType = setup.data.Length > 0 ? setup.data[0] : (byte)0xFF;
        string deviceClass = unitType switch
        {
            0x06 => "NOTE_RECYCLER",   // NV200 / Spectral Payout (billetes)
            0x09 => "COIN_SYSTEM",     // Smart Coin System / Hopper (monedas)
            _ => $"UNKNOWN_0x{unitType:X2}"
        };

        // Dataset y canales según tipo; para monedas, extraemos valores por canal
        string dataset = "unknown";
        int channelCount = 0;
        List<decimal> coinValues = new();

        if (unitType == 0x09)
        {
            // Smart Coin System: dataset en [5..7], nº canales en [9], valores a partir de [10], 2 bytes LE por canal (centésimas)
            if (setup.data.Length >= 8) dataset = Encoding.ASCII.GetString(setup.data, 5, 3);
            if (setup.data.Length >= 10) channelCount = setup.data[9];
            int off = 10;
            for (int i = 0; i < channelCount; i++)
            {
                if (off + 1 < setup.data.Length)
                {
                    int cents = setup.data[off] | (setup.data[off + 1] << 8);
                    coinValues.Add(cents / 100m);
                }
                off += 2;
            }
        }
        else
        {
            // Payout de billetes (unitType 0x06): heurística prudente
            dataset = TryAscii3(setup.data, 5) ?? "unknown";
            channelCount = TryByte(setup.data, 11);
            if (channelCount < 0 || channelCount > 64) channelCount = 0;
        }

        // Firmware (0x20) — opcional
        string firmware = "";
        var fw = ssp.SendWithData(new byte[] { 0x20 });
        if (fw.ok)
        {
            try
            {
                firmware = Encoding.ASCII.GetString(fw.data).Trim('\0');
                Log($"Firmware string: {firmware}");
            }
            catch { /* ignoramos si no es ASCII limpio */ }
        }
        else
        {
            Log($"Get Firmware Version not available: {fw.statusHex}");
        }

        // Modelo (heurística): si el firmware contiene “NV…”
        string model = "";
        if (!string.IsNullOrEmpty(firmware))
        {
            int idx = firmware.IndexOf("NV", StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                int len = Math.Min(10, firmware.Length - idx);
                if (len > 0) model = firmware.Substring(idx, len).Trim();
            }
        }
        if (string.IsNullOrWhiteSpace(model)) model = "ITL NV200 / Spectral Payout (detected)";

        var channels = Enumerable.Range(1, Math.Max(0, channelCount)).ToArray();

        // JSON del dispositivo (objeto)
        var json = new StringBuilder();
        json.Append("{");
        json.Append("\"status\":\"HEALTH_OK\"");
        json.Append($",\"port\":{J(port)}");
        json.Append($",\"baud\":9600");
        json.Append($",\"address\":{addr}");
        json.Append($",\"protocol\":{protocolAccepted}");
        json.Append($",\"dataset\":{J(dataset)}");
        json.Append($",\"model\":{J(model)}");
        json.Append($",\"firmware\":{J(firmware)}");
        json.Append($",\"unitType\":{unitType}");
        json.Append($",\"deviceClass\":{J(deviceClass)}");
        json.Append(",\"channels\":[");
        for (int i = 0; i < channels.Length; i++)
        {
            if (i > 0) json.Append(",");
            json.Append(channels[i]);
        }
        json.Append("]");

        if (deviceClass == "COIN_SYSTEM" && coinValues.Count > 0)
        {
            json.Append(",\"coinValues\":[");
            for (int i = 0; i < coinValues.Count; i++)
            {
                if (i > 0) json.Append(",");
                json.Append(coinValues[i].ToString(CultureInfo.InvariantCulture));
            }
            json.Append("]");
        }

        json.Append("}");
        return (true, json.ToString());
    }

    // ---------- utilidades (JSON/logs/parsers simples) ----------
    static string J(string s) => "\"" + (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    static void Log(string m) => Console.Error.WriteLine("[INFO] " + m);
    static void Error(string m) => Console.Error.WriteLine("[ERR ] " + m);
    static string ToHex(IEnumerable<byte> bytes) => string.Join(" ", bytes.Select(b => b.ToString("X2")));
    static string? TryAscii3(byte[] data, int offset)
    {
        try
        {
            if (data.Length >= offset + 3)
            {
                var s = Encoding.ASCII.GetString(data, offset, 3);
                if (s.All(c => c >= 'A' && c <= 'Z')) return s;
            }
        }
        catch { }
        return null;
    }
    static int TryByte(byte[] data, int offset)
    {
        try { return (data.Length > offset) ? data[offset] : -1; }
        catch { return -1; }
    }
}

//
// SspWire — capa “de cable” eSSP a bajo nivel (sin DLL de ITL)
// - Construye tramas: STX(0x7F) + (SEQ|ADDR) + LEN + DATA + CRC(0x8005)
// - Aplica byte-stuffing de 0x7F y alterna el bit de secuencia (0/1)
// - Proporciona SendSimple (solo status) y SendWithData (status + datos)
//
class SspWire
{
    private readonly SerialPort _sp;
    private readonly byte _addr;
    private byte _seq;
    private readonly Action<string> _log;

    public SspWire(SerialPort sp, byte addr, byte initialSeq, Action<string> logger)
    {
        _sp = sp;
        // Dirección del dispositivo eSSP en el bus (normalmente 0; el Smart Coin suele ser 16)
        _addr = addr;
        // Bit de secuencia inicial (0/1); alterna en cada envío para evitar replays
        _seq = initialSeq;
        _log = logger ?? (_ => { });
    }

    public (bool ok, string statusHex) SendSimple(byte[] payload)
    {
        var rx = SendPacket(payload);
        if (rx == null || rx.Length == 0) return (false, "(no reply)");
        return (rx[0] == 0xF0, "0x" + rx[0].ToString("X2")); // 0xF0 => OK
    }

    public (bool ok, byte[] data, string statusHex) SendWithData(byte[] payload)
    {
        var rx = SendPacket(payload);
        if (rx == null || rx.Length == 0) return (false, Array.Empty<byte>(), "(no reply)");
        bool ok = rx[0] == 0xF0;
        var data = ok ? rx.Skip(1).ToArray() : Array.Empty<byte>(); // quita status
        return (ok, data, "0x" + rx[0].ToString("X2"));
    }

    private byte[] SendPacket(byte[] payload)
    {
        // (SEQ|ADDR) | LEN | DATA... | CRC16
        var frame = new List<byte>();
        byte addrSeq = (byte)(((_seq & 0x01) << 7) | (_addr & 0x7F));
        frame.Add(addrSeq);
        frame.Add((byte)payload.Length);
        frame.AddRange(payload);

        ushort crc = Crc16(frame);
        frame.Add((byte)(crc & 0xFF));        // CRCL
        frame.Add((byte)((crc >> 8) & 0xFF)); // CRCH

        // Stuffing con STX=0x7F + duplicación de 0x7F en datos
        var tx = new List<byte> { 0x7F };
        foreach (var b in frame)
        {
            tx.Add(b);
            if (b == 0x7F) tx.Add(0x7F);
        }

        _sp.DiscardInBuffer();
        _sp.Write(tx.ToArray(), 0, tx.Count);
        _log($"TX(stuffed): {Hex(tx)}");
        _seq ^= 1; // alternar bit de secuencia

        // RX: esperar STX y deshacer stuffing
        if (!WaitForByte(0x7F)) { _log("RX: no STX"); return null; }

        var unstuff = new List<byte>();
        int expected = -1;
        DateTime t0 = DateTime.UtcNow;

        while (true)
        {
            int b = ReadByte();
            if (b < 0) { _log("RX: timeout"); return null; }

            if (b == 0x7F)
            {
                // 0x7F duplicado => dato 0x7F
                int next = ReadByte();
                if (next < 0) { _log("RX: timeout post-0x7F"); return null; }
                if (next == 0x7F) unstuff.Add(0x7F);
                else unstuff.Add((byte)next);
            }
            else
            {
                unstuff.Add((byte)b);
            }

            // Cuando tenemos addr+len, sabemos el tamaño esperado (addr+len+data+crc)
            if (unstuff.Count == 2 && expected < 0)
            {
                int len = unstuff[1];
                expected = 1 + 1 + len + 2;
            }

            if (expected > 0 && unstuff.Count >= expected) break;

            if ((DateTime.UtcNow - t0).TotalMilliseconds > _sp.ReadTimeout + 500)
            {
                _log("RX: overall timeout");
                return null;
            }
        }

        _log($"RX(unstuffed): {Hex(unstuff)}");

        // Verificar CRC del paquete
        ushort calc = Crc16(unstuff.Take(expected - 2));
        byte crcl = unstuff[expected - 2];
        byte crch = unstuff[expected - 1];
        if (((calc & 0xFF) != crcl) || (((calc >> 8) & 0xFF) != crch))
        {
            _log($"RX: CRC mismatch. calc={calc:X4} vs got={(crch << 8) | crcl:X4}");
            return null;
        }

        // Devuelve solo la “carga” (status + datos), omitiendo addr,len,crc
        return unstuff.Skip(2).Take(expected - 4).ToArray();
    }

    private bool WaitForByte(byte value)
    {
        int b;
        do { b = ReadByte(); if (b < 0) return false; } while (b != value);
        return true;
    }

    private int ReadByte()
    {
        try { return _sp.ReadByte(); } catch { return -1; }
    }

    // CRC-16 polinomio 0x8005, seed 0xFFFF (especificación eSSP)
    private static ushort Crc16(IEnumerable<byte> data)
    {
        ushort crc = 0xFFFF;
        foreach (byte b in data)
        {
            crc ^= (ushort)(b << 8);
            for (int i = 0; i < 8; i++)
            {
                bool msb = (crc & 0x8000) != 0;
                crc <<= 1;
                if (msb) crc ^= 0x8005;
            }
        }
        return crc;
    }

    private static string Hex(IEnumerable<byte> bytes)
        => string.Join(" ", bytes.Select(x => x.ToString("X2")));
}
