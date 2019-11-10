Linux Example:
[DllImport("libc")]
static extern int read(int handle, byte[] buf, int n);

[DllImport("libc.so.6")]
private static extern int getpid();

[DllImport("libgtk-x11-2.0.so.0")]
static extern IntPtr gtk_message_dialog_new(IntPtr parent_window, DialogFlags flags, MessageType type, ButtonsType bt, string msg, IntPtr args);

Windows Functions are most likely the same.

Can we [DllImport("ldap")]?
