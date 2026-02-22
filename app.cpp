#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <ctime>
#include <sys/utsname.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>

using namespace std;

// Credentials
const string AUTH_USER = "root";
const string AUTH_PASS = "nxrpass";
const string SESSION_COOKIE = "session_id=nxr_authenticated_123";

// Terminal Colors
#define RESET   "\033[0m"
#define GREEN   "\033[32m"
#define BOLD    "\033[1m"

const int MAX_LOGS = 100;
vector<string> connectionLogs;

// ---------------- Utility Functions ---------------- //

int getCpuCores() {
    ifstream cpuinfo("/proc/cpuinfo");
    string line;
    int cores = 0;
    while (getline(cpuinfo, line)) {
        if (line.find("processor") != string::npos) cores++;
    }
    return cores > 0 ? cores : 1;
}

pair<int,int> getMemoryInfo() {
    ifstream meminfo("/proc/meminfo");
    string line;
    int memTotal = 0, memAvailable = 0;
    while (getline(meminfo, line)) {
        if (line.find("MemTotal:") != string::npos) sscanf(line.c_str(), "MemTotal: %d kB", &memTotal);
        if (line.find("MemAvailable:") != string::npos) sscanf(line.c_str(), "MemAvailable: %d kB", &memAvailable);
    }
    return {(memTotal - memAvailable) / 1024, memTotal / 1024};
}

string getUptime() {
    struct sysinfo info;
    if (::sysinfo(&info) != 0) return "00:00:00";
    long uptimeSec = info.uptime;
    int h = uptimeSec / 3600, m = (uptimeSec % 3600) / 60, s = uptimeSec % 60;
    char buf[20];
    sprintf(buf, "%02d:%02d:%02d", h, m, s);
    return string(buf);
}

string getHostname() {
    char buf[128];
    ::gethostname(buf, sizeof(buf));
    return string(buf);
}

void replaceAll(string &str, const string &from, const string &to) {
    size_t start = 0;
    while ((start = str.find(from, start)) != string::npos) {
        str.replace(start, from.length(), to);
        start += to.length();
    }
}

// লগিং ফাংশন (এজেন্ট লিমিট ২৪০ ক্যারেক্টার)
void addConnectionLog(const string &ip, const string &method, const string &endpoint, const string &agent) {
    time_t now = time(nullptr);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    // এজেন্ট লিমিট ২৪০ ক্যারেক্টার করা হয়েছে
    string shortAgent = (agent.length() > 240) ? agent.substr(0, 237) + "..." : agent;

    string logEntry = "<tr><td class='px-4 py-2 text-gray-500'>" + string(ts) + 
                      "</td><td class='px-4 py-2 text-blue-400 font-bold'>" + ip + 
                      "</td><td class='px-4 py-2 text-green-400 font-bold'>" + method + 
                      "</td><td class='px-4 py-2 text-yellow-400 font-bold'>" + endpoint + 
                      "</td><td class='px-4 py-2 text-xs opacity-60'>" + shortAgent + "</td></tr>";
    
    connectionLogs.push_back(logEntry);
    if (connectionLogs.size() > MAX_LOGS) connectionLogs.erase(connectionLogs.begin());
}

// ---------------- Main Server ---------------- //
int main() {
    int server_fd;
    struct sockaddr_in address;
    server_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    ::setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if (::bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed"); return 1;
    }

    ::listen(server_fd, 10);
    cout << GREEN << BOLD << "\n * NXR Secure Server Started Successfully" << RESET << endl;
    cout << GREEN << " * Control Panel: " << BOLD << "http://127.0.0.1:8080/login" << RESET << endl;

    while (true) {
        int addrlen = sizeof(address);
        int new_socket = ::accept(server_fd, (sockaddr*)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) continue;

        char buffer[30000] = {0};
        ::read(new_socket, buffer, sizeof(buffer));
        string request(buffer);
        if (request.empty()) { ::close(new_socket); continue; }

        string ip = inet_ntoa(address.sin_addr);
        string method = "GET", endpoint = "/";
        size_t mEnd = request.find(" "), eEnd = request.find(" ", mEnd + 1);
        if (mEnd != string::npos && eEnd != string::npos) {
            method = request.substr(0, mEnd);
            endpoint = request.substr(mEnd + 1, eEnd - mEnd - 1);
        }

        bool isAuthenticated = (request.find(SESSION_COOKIE) != string::npos);
        string response;

        // --- Routing Logic ---
        
        if (method == "POST" && endpoint == "/login") {
            if (request.find("username=" + AUTH_USER) != string::npos && 
                request.find("password=" + AUTH_PASS) != string::npos) {
                response = "HTTP/1.1 302 Found\r\nLocation: /dashboard\r\nSet-Cookie: " + SESSION_COOKIE + "; Path=/; HttpOnly\r\n\r\n";
            } else {
                response = "HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n";
            }
        } 
        else if (endpoint == "/logout") {
            response = "HTTP/1.1 302 Found\r\nLocation: /login\r\nSet-Cookie: session_id=; Max-Age=0; Path=/\r\n\r\n";
        }
        else if (endpoint == "/dashboard") {
            if (!isAuthenticated) {
                response = "HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n";
            } else {
                ifstream file("dashboard.html");
                if(!file) { response = "HTTP/1.1 404 Not Found\r\n\r\nDashboard missing!"; }
                else {
                    stringstream ss; ss << file.rdbuf();
                    string content = ss.str();
                    auto mem = getMemoryInfo();
                    struct utsname ub; uname(&ub);
                    
                    replaceAll(content, "{{CPU_CORES}}", to_string(getCpuCores()));
                    replaceAll(content, "{{ARCHITECTURE}}", string(ub.machine));
                    replaceAll(content, "{{MEMORY_USED}}", to_string(mem.first));
                    replaceAll(content, "{{MEMORY_TOTAL}}", to_string(mem.second));
                    replaceAll(content, "{{MEMORY_PERCENT}}", to_string((mem.second > 0) ? (mem.first * 100 / mem.second) : 0));
                    replaceAll(content, "{{UPTIME}}", getUptime());
                    replaceAll(content, "{{HOSTNAME}}", getHostname());
                    replaceAll(content, "{{KERNEL_VERSION}}", string(ub.release));
                    replaceAll(content, "{{PLATFORM}}", string(ub.sysname));
                    
                    string logs;
                    for (int i = connectionLogs.size() - 1; i >= 0; i--) logs += connectionLogs[i];
                    replaceAll(content, "{{CONNECTION_LOG}}", logs);
                    response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + content;
                }
            }
        }
        else if (endpoint == "/login") {
            ifstream file("login.html");
            if(!file) response = "HTTP/1.1 200 OK\r\n\r\nLogin file missing!";
            else {
                stringstream ss; ss << file.rdbuf();
                response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + ss.str();
            }
        }
        else if (endpoint == "/" || endpoint == "/index.html") {
            ifstream file("index.html");
            if(!file) response = "HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n";
            else {
                stringstream ss; ss << file.rdbuf();
                response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + ss.str();
            }
        }
        else if (endpoint == "/favicon.ico") {
            response = "HTTP/1.1 204 No Content\r\n\r\n";
        }
        else {
            response = "HTTP/1.1 404 Not Found\r\n\r\nNot Found";
        }

        ::send(new_socket, response.c_str(), response.size(), 0);
        
        // --- Filtering Logs (শুধুমাত্র মেইন পেজগুলো লগ হবে) ---
        if (endpoint == "/" || endpoint == "/index.html" || endpoint == "/dashboard" || endpoint == "/login") {
            string agent = "Unknown";
            size_t uaPos = request.find("User-Agent: ");
            if (uaPos != string::npos) {
                size_t uaEnd = request.find("\r\n", uaPos);
                agent = request.substr(uaPos + 12, uaEnd - (uaPos + 12));
            }
            addConnectionLog(ip, method, endpoint, agent);
        }

        ::close(new_socket);
    }
    return 0;
}