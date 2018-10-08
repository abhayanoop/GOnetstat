package GOnetstat

type Process struct {
    User         string
    Name         string
    Pid          string
    Exe          string
    State        string
    Ip           string
    Port         int64
    ForeignIp    string
    ForeignPort  int64
}