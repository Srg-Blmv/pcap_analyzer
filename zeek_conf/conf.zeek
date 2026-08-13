@load ./Zeek-Intelligence-Feeds/main
@load frameworks/files/hash-all-files
@load ja4
redef FTP::default_capture_password = T;
redef FTP::logged_commands += {"PASS"};
