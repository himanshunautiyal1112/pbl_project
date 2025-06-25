// server.cpp - Multithreaded Web Server
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <map>
#include <vector>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <filesystem>
#include <mutex>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>

namespace fs = std::filesystem;
std::mutex logMutex;
std::map<std::string, bool> sessions;

std::string getMimeType(const std::string& path) {
    if (path.size() >= 5 && path.substr(path.size() - 5) == ".html") return "text/html";
    if (path.size() >= 4 && path.substr(path.size() - 4) == ".jpg") return "image/jpeg";
    if (path.size() >= 4 && path.substr(path.size() - 4) == ".pdf") return "application/pdf";
    if (path.size() >= 4 && path.substr(path.size() - 4) == ".mp4") return "video/mp4";
    if (path.size() >= 4 && path.substr(path.size() - 4) == ".jpg") return "image/jpeg";
    if (path.size() >= 4 && path.substr(path.size() - 4) == ".png") return "image/png";
    if (path.size() >= 4 && path.substr(path.size() - 4) == ".gif") return "image/gif";

    return "text/plain";
}

 // already included for threading

void logRequest(const std::string& ip, const std::string& path) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::ofstream log("log.txt", std::ios::app);
    log << "[Thread " << std::this_thread::get_id() << "] "
        << ip << " requested " << path << std::endl;
}


void sendResponse(int clientSocket, const std::string& status, const std::string& contentType, const std::string& body) {
    std::ostringstream response;
    response << "HTTP/1.1 " << status << "\r\n";
    response << "Content-Type: " << contentType << "\r\n";
    response << "Content-Length: " << body.length() << "\r\n";
    response << "Connection: close\r\n\r\n";
    response << body;
    std::string resStr = response.str();
    send(clientSocket, resStr.c_str(), resStr.length(), 0);
}

void serveFile(int clientSocket, const std::string& path) {
    if (!fs::exists(path)) {
        sendResponse(clientSocket, "404 Not Found", "text/plain", "404 Not Found");
        return;
    }

    std::ifstream file(path, std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> buffer(size);
    file.read(buffer.data(), size);

    std::ostringstream header;
    header << "HTTP/1.1 200 OK\r\n";
    header << "Content-Type: " << getMimeType(path) << "\r\n";
    header << "Content-Length: " << size << "\r\n";
    header << "Connection: close\r\n\r\n";

    std::string headerStr = header.str();
    send(clientSocket, headerStr.c_str(), headerStr.length(), 0);
    send(clientSocket, buffer.data(), size, 0);
}


void handleImageUpload(int clientSocket, const std::string& request) {
    // Extract boundary from Content-Type header
    size_t boundaryPos = request.find("boundary=");
    if (boundaryPos == std::string::npos) {
        sendResponse(clientSocket, "400 Bad Request", "text/plain", "Missing boundary");
        return;
    }

    std::string boundary = "--" + request.substr(boundaryPos + 9, request.find("\r\n", boundaryPos) - (boundaryPos + 9));

    // Extract start of body
    size_t bodyStart = request.find("\r\n\r\n");
    if (bodyStart == std::string::npos) {
        sendResponse(clientSocket, "400 Bad Request", "text/plain", "Invalid request structure");
        return;
    }

    std::string body = request.substr(bodyStart + 4);

    // Find start of file part
    size_t fileHeaderStart = body.find("Content-Disposition");
    if (fileHeaderStart == std::string::npos) {
        sendResponse(clientSocket, "400 Bad Request", "text/plain", "Missing Content-Disposition");
        return;
    }

    // Extract filename
    std::string filename = "uploaded_file";
    std::string filenameKey = "filename=\"";
    size_t fnamePos = body.find(filenameKey, fileHeaderStart);
    if (fnamePos != std::string::npos) {
        size_t fnameStart = fnamePos + filenameKey.length();
        size_t fnameEnd = body.find("\"", fnameStart);
        filename = body.substr(fnameStart, fnameEnd - fnameStart);
        filename = fs::path(filename).filename().string(); // sanitize path
    }

    // Find start of file content (after 2 CRLFs from headers)
    size_t fileContentStart = body.find("\r\n\r\n", fileHeaderStart);
    if (fileContentStart == std::string::npos) {
        sendResponse(clientSocket, "400 Bad Request", "text/plain", "Malformed upload body");
        return;
    }
    fileContentStart += 4;

    // Find end of file content using boundary
    size_t fileContentEnd = body.find(boundary, fileContentStart);
    if (fileContentEnd == std::string::npos) {
        sendResponse(clientSocket, "400 Bad Request", "text/plain", "Boundary not found in body");
        return;
    }

    std::string fileData = body.substr(fileContentStart, fileContentEnd - fileContentStart);

    // Write file to uploads directory
    std::ofstream out("uploads/" + filename, std::ios::binary);
    if (!out) {
        sendResponse(clientSocket, "500 Internal Server Error", "text/plain", "Failed to write file");
        return;
    }

    out.write(fileData.c_str(), fileData.size());
    out.close();

    // Send success response
    std::ostringstream response;
    response << "<h2>✅ Image Uploaded Successfully</h2>";
    response << "<img src='/uploads/" << filename << "' alt='Uploaded Image' style='max-width: 500px;'/><br><br>";
    response << "<a href='/upload.html'>Upload Another</a> | <a href='/'>Home</a>";
    sendResponse(clientSocket, "200 OK", "text/html", response.str());
}



void listFiles(int clientSocket) {
    std::ostringstream body;
    body << "<h2>Uploaded PDFs</h2><ul>";
    for (const auto& entry : fs::directory_iterator("uploads")) {
        std::string name = entry.path().filename();
        body << "<li><a href='/uploads/" << name << "'>" << name << "</a></li>";
    }
    body << "</ul><a href='/html/index.html'>Back</a>";
    sendResponse(clientSocket, "200 OK", "text/html", body.str());
}

void handleLogin(int clientSocket, const std::string& body, const std::string& ip) {
    std::string username = "", password = "";
    size_t uPos = body.find("username=");
    size_t pPos = body.find("&password=");
    if (uPos != std::string::npos && pPos != std::string::npos) {
        username = body.substr(uPos + 9, pPos - (uPos + 9));
        password = body.substr(pPos + 10);
    }

    if (username == "admin" && password == "admin") {
        sessions[ip] = true;
        sendResponse(clientSocket, "200 OK", "text/html", "<h2>Login Success</h2><a href='/index.html'>Go Home</a>");
    } else {
        sendResponse(clientSocket, "401 Unauthorized", "text/html", "<h2>Invalid Credentials</h2><a href='/login'>Try Again</a>");
    }
}

void handleClient(int clientSocket, sockaddr_in clientAddr) {
    std::cout << "[*] Client connected: " << inet_ntoa(clientAddr.sin_addr) << std::endl;

    std::string request;
char buffer[8192];
int bytesRead;

// First read (likely contains headers)
bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
if (bytesRead <= 0) {
    std::cerr << "[!] recv() failed or empty. Closing connection." << std::endl;
    close(clientSocket);
    return;
}
request.append(buffer, bytesRead);

// Try to get Content-Length
size_t contentLengthPos = request.find("Content-Length:");
if (contentLengthPos != std::string::npos) {
    size_t endLine = request.find("\r\n", contentLengthPos);
    std::string lenStr = request.substr(contentLengthPos + 15, endLine - (contentLengthPos + 15));
    int contentLength = std::stoi(lenStr);

    size_t headerEnd = request.find("\r\n\r\n");
    size_t currentBodySize = request.size() - (headerEnd + 4);

    while (currentBodySize < contentLength) {
        bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesRead <= 0) break;
        request.append(buffer, bytesRead);
        currentBodySize += bytesRead;
    }
}

    std::istringstream reqStream(request);
    std::string method, path;
    reqStream >> method >> path;

    std::string ip = inet_ntoa(clientAddr.sin_addr);
    logRequest(ip, path);

    if (path == "/" || path == "/login.html") {
        serveFile(clientSocket, "html/login.html");
    } else if (path == "/login" && method == "POST") {
        std::string body = request.substr(request.find("\r\n\r\n") + 4);
        handleLogin(clientSocket, body, ip);
    } else if (path == "/login") {
        serveFile(clientSocket, "html/login.html");
    } else if (path == "/upload" && method == "POST") {
        if (sessions[ip]) handleImageUpload(clientSocket, request);
        else sendResponse(clientSocket, "403 Forbidden", "text/plain", "Please login first");
    } else if (path == "/upload.html") {
        serveFile(clientSocket, "html/upload.html");
    } else if (path == "/developers") {
        serveFile(clientSocket, "html/developers.html");
    } else if (path.substr(0, 11) == "/developer/") {
        serveFile(clientSocket, "html" + path + ".html");
    } else if (path == "/files") {
        listFiles(clientSocket);
    } else if (path.substr(0, 9) == "/uploads/") {
        serveFile(clientSocket, path.substr(1));
    } else {
        serveFile(clientSocket, "html" + path);
    }

    close(clientSocket);
}

int main() {
    mkdir("uploads", 0777);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        return 1;
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        return 1;
    }

    std::cout << "🚀 Server running on port 8080..." << std::endl;

    while (true) {
        sockaddr_in clientAddr;
        socklen_t addrLen = sizeof(clientAddr);
        int clientSocket = accept(server_fd, (sockaddr*)&clientAddr, &addrLen);
        if (clientSocket < 0) {
            perror("accept failed");
            continue;
        }
        std::thread(handleClient, clientSocket, clientAddr).detach();
    }

    return 0;
}

