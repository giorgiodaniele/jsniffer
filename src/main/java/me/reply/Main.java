package me.reply;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IcmpV4Type;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class Main {

    private static final DateTimeFormatter TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
                    .withZone(ZoneId.systemDefault());

    private static PrintWriter fileWriter = null;

    // CLI options
    private static String protoFilter = "all";
    private static Integer sportFilter = null;
    private static Integer dportFilter = null;

    public static void main(String[] args) {
        Map<String, String> options = parseArgs(args);

        if (options.containsKey("help")) {
            printHelp();
            return;
        }

        // Parse filters
        if (options.containsKey("proto")) {
            protoFilter = options.get("proto").toLowerCase();
        }
        if (options.containsKey("sport")) {
            sportFilter = Integer.parseInt(options.get("sport"));
        }
        if (options.containsKey("dport")) {
            dportFilter = Integer.parseInt(options.get("dport"));
        }

        try {
            if (options.containsKey("out")) {
                fileWriter = new PrintWriter(new FileWriter(options.get("out"), true));
                System.out.println("[INFO] Logging packets to file: " + options.get("out"));
            }

            PcapNetworkInterface nif = getFirstNetworkInterface();
            if (nif == null) {
                System.err.println("[ERR] No network interfaces found.");
                return;
            }

            System.out.println("[INFO] Selected interface: "
                    + nif.getName() + " - " + nif.getDescription());

            PcapHandle handle = openHandle(nif);

            System.out.println("[INFO] Filters: proto=" + protoFilter
                    + (sportFilter != null ? " sport=" + sportFilter : "")
                    + (dportFilter != null ? " dport=" + dportFilter : ""));

            startSniffing(handle);

            handle.close();

        } catch (PcapNativeException | NotOpenException e) {
            System.err.println("[ERR] " + e.getMessage());
            e.printStackTrace();
        } catch (InterruptedException e) {
            System.out.println("[WARN] Sniffer interrupted.");
        } catch (IOException e) {
            System.err.println("[ERR] File error: " + e.getMessage());
        } finally {
            if (fileWriter != null) {
                fileWriter.close();
            }
        }
    }

    // Parse CLI arguments
    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--help":
                case "-h":
                case "-help":
                    map.put("help", "");
                    break;
                case "--out":
                case "-o":
                    if (i + 1 < args.length) {
                        map.put("out", args[++i]);
                    }
                    break;
                case "--proto":
                case "-p":
                    if (i + 1 < args.length) {
                        map.put("proto", args[++i]);
                    }
                    break;
                case "--sport":
                    if (i + 1 < args.length) {
                        map.put("sport", args[++i]);
                    }
                    break;
                case "--dport":
                    if (i + 1 < args.length) {
                        map.put("dport", args[++i]);
                    }
                    break;
            }
        }
        return map;
    }

    private static void printHelp() {
        System.out.println("Usage: java -jar sniffer.jar [options]\n");
        System.out.println("Options:");
        System.out.println("  -h, --help           Show this help message");
        System.out.println("  -o, --out <file>     Save captured packets to file");
        System.out.println("  -p, --proto <proto>  Filter protocol: tcp, udp, icmp, all (default=all)");
        System.out.println("  --sport <port>       Filter by source port");
        System.out.println("  --dport <port>       Filter by destination port");
        System.out.println("\nExamples:");
        System.out.println("  java -jar sniffer.jar --proto tcp --sport 80");
        System.out.println("  java -jar sniffer.jar --proto udp --dport 53 --out dns.log");
    }

    private static PcapNetworkInterface getFirstNetworkInterface()
            throws PcapNativeException {
        List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
        if (nifs == null || nifs.isEmpty()) {
            return null;
        }
        return nifs.get(0);
    }

    private static PcapHandle openHandle(PcapNetworkInterface nif)
            throws PcapNativeException {
        int snapLen = 65536;
        PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
        int timeout = 10;
        return nif.openLive(snapLen, mode, timeout);
    }

    private static void startSniffing(PcapHandle handle)
            throws PcapNativeException, NotOpenException, InterruptedException {
        PacketListener listener = packet -> {
            if (shouldKeep(packet)) {
                formatAndPrintPacket(handle, packet);
            }
        };
        handle.loop(-1, listener);
    }

    // Java-side filtering
    private static boolean shouldKeep(Packet packet) {
        if (!packet.contains(IpV4Packet.class)) {
            return false; // drop non-IP
        }

        IpV4Packet ip = packet.get(IpV4Packet.class);
        IpNumber proto = ip.getHeader().getProtocol();

        switch (protoFilter) {
            case "tcp":
                if (!proto.equals(IpNumber.TCP)) return false;
                if (packet.contains(TcpPacket.class)) {
                    TcpPacket tcp = packet.get(TcpPacket.class);
                    int sport = tcp.getHeader().getSrcPort().valueAsInt();
                    int dport = tcp.getHeader().getDstPort().valueAsInt();
                    if (sportFilter != null && sport != sportFilter) return false;
                    if (dportFilter != null && dport != dportFilter) return false;
                }
                break;
            case "udp":
                if (!proto.equals(IpNumber.UDP)) return false;
                if (packet.contains(UdpPacket.class)) {
                    UdpPacket udp = packet.get(UdpPacket.class);
                    int sport = udp.getHeader().getSrcPort().valueAsInt();
                    int dport = udp.getHeader().getDstPort().valueAsInt();
                    if (sportFilter != null && sport != sportFilter) return false;
                    if (dportFilter != null && dport != dportFilter) return false;
                }
                break;
            case "icmp":
                if (!proto.equals(IpNumber.ICMPV4)) return false;
                break;
            case "all":
            default:
                break;
        }
        return true;
    }

    private static void formatAndPrintPacket(PcapHandle handle, Packet packet) {
        try {
            String timestamp = TIME_FORMATTER.format(handle.getTimestamp().toInstant());

            StringBuilder sb = new StringBuilder();

            if (packet.contains(IpV4Packet.class)) {
                IpV4Packet ipPacket = packet.get(IpV4Packet.class);
                String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
                String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();
                IpNumber protocol = ipPacket.getHeader().getProtocol();

                if (protocol.equals(IpNumber.TCP) && packet.contains(TcpPacket.class)) {
                    TcpPacket tcp = packet.get(TcpPacket.class);
                    int sport = tcp.getHeader().getSrcPort().valueAsInt();
                    int dport = tcp.getHeader().getDstPort().valueAsInt();

                    String flags = buildTcpFlags(tcp);
                    long seq = tcp.getHeader().getSequenceNumberAsLong();
                    long ack = tcp.getHeader().getAcknowledgmentNumberAsLong();
                    int win = tcp.getHeader().getWindowAsInt();

                    sb.append(String.format(
                            "%s TCP srcip=%s dstip=%s sport=%d dport=%d flags=%s seq=%d ack=%d win=%d length=%d",
                            timestamp, srcIp, dstIp, sport, dport, flags, seq, ack, win, tcp.length()
                    ));

                } else if (protocol.equals(IpNumber.UDP) && packet.contains(UdpPacket.class)) {
                    UdpPacket udp = packet.get(UdpPacket.class);
                    int sport = udp.getHeader().getSrcPort().valueAsInt();
                    int dport = udp.getHeader().getDstPort().valueAsInt();
                    int udpLen = udp.getHeader().getLengthAsInt();

                    sb.append(String.format(
                            "%s UDP srcip=%s dstip=%s sport=%d dport=%d length=%d",
                            timestamp, srcIp, dstIp, sport, dport, udpLen
                    ));

                } else if (protocol.equals(IpNumber.ICMPV4) && packet.contains(IcmpV4CommonPacket.class)) {
                    IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
                    IcmpV4Type type = icmp.getHeader().getType();
                    int code = icmp.getHeader().getCode().value();

                    sb.append(String.format(
                            "%s ICMP srcip=%s dstip=%s type=%s code=%d checksum=0x%04x",
                            timestamp, srcIp, dstIp, type, code, icmp.getHeader().getChecksum()
                    ));
                }
            }

            String line = sb.toString();
            if (!line.isEmpty()) {
                System.out.println(line);
                if (fileWriter != null) {
                    fileWriter.println(line);
                    fileWriter.flush();
                }
            }

        } catch (Exception e) {
            System.err.println("[ERR] Error formatting packet: " + e.getMessage());
        }
    }

    private static String buildTcpFlags(TcpPacket tcp) {
        StringBuilder flags = new StringBuilder("[");
        TcpPacket.TcpHeader h = tcp.getHeader();
        if (h.getSyn()) flags.append("S");
        if (h.getAck()) flags.append("A");
        if (h.getPsh()) flags.append("P");
        if (h.getFin()) flags.append("F");
        if (h.getRst()) flags.append("R");
        if (h.getUrg()) flags.append("U");
        flags.append("]");
        return flags.toString();
    }
}
