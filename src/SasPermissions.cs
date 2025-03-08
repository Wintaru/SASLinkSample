using System;

[Flags]
public enum SasPermissions
{
    Read = 1 << 0,   // 1
    Write = 1 << 1,  // 2
    Delete = 1 << 2, // 4
    List = 1 << 3,   // 8
    Add = 1 << 4,    // 16
    Create = 1 << 5, // 32
    Update = 1 << 6, // 64
    Process = 1 << 7 // 128
}
