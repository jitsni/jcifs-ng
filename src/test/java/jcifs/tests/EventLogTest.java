package jcifs.tests;

import jcifs.CIFSContext;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.dcerpc.*;
import jcifs.dcerpc.msrpc.eventlog;
import jcifs.smb.*;

import java.io.IOException;
import java.util.*;

public class EventLogTest {

    private DcerpcHandle rpcHandle;

    private rpc.policy_handle policyHandle;

    //Make sure netstat on event log server is listening on :445
    //For some reason, it was not until I deselected/selected file sharing
    //Establish a ssh tunnel
    //sudo ssh -f Administrator@10.192.39.247 -L 445:127.0.0.1:445 -N
    //private final String hostname = "10.192.39.247";
    private final String hostname = "127.0.0.1";
    private final String domain = "";
    private final String user = "";
    private final String password = "";

    public static void main(String ... args) throws Exception {
        EventLogTest eventLogTest = new EventLogTest();
        eventLogTest.connect();
    }

    private void connect() throws Exception {
        try {
            openRPCConnection();
            openEventLog();

            long offset = retrieveOldestRecordID();
            eventlog.EventLogReadEventLog re =
                    new eventlog.EventLogReadEventLog(policyHandle,
                            eventlog.EVENTLOG_SEEK_READ | eventlog.EVENTLOG_FORWARDS_READ,
                            (int) offset, 16384);

            rpcHandle.sendrecv(re);
            checkNtStatus(re.retval);
            if (re.entries != null) {
                for (Object o : re.entries) {
                    eventlog.EventlogRecord entry = (eventlog.EventlogRecord) o;
                    if (entry.event_id == 4624) {
                        System.out.printf("LOGON %d source = %s computer=%s strings=%s\n",
                                entry.event_type, entry.source_name, entry.computer_name, Arrays.toString(entry.strings));
                    } else if (entry.event_id == 4634) {
                        System.out.printf("LOGOFFsource = %s computer=%s strings=%s\n",
                                entry.source_name, entry.computer_name, Arrays.toString(entry.strings));
                    }
                }
            }

        } catch (Exception e) {
            System.out.println("Eventlog exception " + e);
        } finally {
            closeEventLog();
            closeRPCConnection();
        }
    }


    private void openRPCConnection() throws Exception {
        CIFSContext context = new BaseContext(new PropertyConfiguration(new Properties()));

        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(context, domain, user, password);
        CIFSContext authContext = context.withCredentials(auth);
        rpcHandle = DcerpcHandle.getHandle("ncacn_np:" + hostname + "[\\PIPE\\eventlog]", authContext);
    }

    private void closeRPCConnection() throws IOException {
        rpcHandle.close();
    }

    private void openEventLog() throws Exception {
        eventlog.EventLogOpenEventLog open = new eventlog.EventLogOpenEventLog(
                new UnicodeString("Security", false),
                new UnicodeString(hostname, false));

        rpcHandle.sendrecv(open);
        checkNtStatus(open.retval);
        policyHandle = open.handle;
    }

    private void closeEventLog() throws Exception  {
        eventlog.EventLogCloseEventLog ce = new eventlog.EventLogCloseEventLog(policyHandle);
        rpcHandle.sendrecv(ce);
        checkNtStatus(ce.retval);
    }

    private long retrieveOldestRecordID() throws DcerpcException, IOException {
        eventlog.EventLogGetOldestEntry go = new eventlog.EventLogGetOldestEntry(policyHandle);

        rpcHandle.sendrecv(go);
        checkNtStatus(go.retval);
        return go.oldestEntryNumber & 0xFFFFFFFFL;
    }

    private void checkNtStatus(int nt_status) {
        System.out.println("NtStatus = " + nt_status);
        // Base on nt_status to throw out exception.
        if (nt_status != NtStatus.NT_STATUS_OK) {
            throw new RuntimeException("Incorrect status = " + nt_status);
        }
     }


//    private SID getUserInfo(eventlog.sid_t sid) {
//        String sidStr = "S-" + (sid.revision & 0xFF) + "-";
//
//        if (sid.identifier_authority[0] != (byte) 0 || sid.identifier_authority[1] != (byte) 0) {
//            sidStr += "0x";
//            sidStr += Hexdump.toHexString(sid.identifier_authority, 0, 6);
//        } else {
//            long shift = 0;
//            long id = 0;
//            for (int i = 5; i > 1; i--) {
//                id += (sid.identifier_authority[i] & 0xFFL) << shift;
//                shift += 8;
//            }
//            sidStr += id;
//        }
//
//        StringBuilder buf = new StringBuilder(sidStr);
//        for (int i = 0; i < sid.sub_authority.length; i++) {
//            buf.append("-");
//            buf.append(String.valueOf(sid.sub_authority[i] & 0xFFFFFFFFL));
//        }
//
//        SID ret = windowsEnvironmentHelper.getUserInfo(getEventlogServer(), buf.toString());
//        return ret;
//    }
//
//    private boolean isResolveSid() {
//        return configurationManager.getConfigurationUnchecked(EVENTLOG_RESOLVSID, true);
//    }
}
