#include <fstream>
#include <string>
#include <vector>
#include <iostream>


#include "configcontroller.h"

#include "include/rapidjson/document.h"
#include "include/rapidjson/writer.h"
#include "include/rapidjson/stringbuffer.h"
#include "include/rapidjson/prettywriter.h"
#include "include/rapidjson/istreamwrapper.h"

std::map<std::string, std::string> ConfigController::m_parameters;

void ConfigController::init()
{
    m_parameters.clear();
    std::string confFile = "../etc/config.json";

    std::ifstream file(confFile);

    if (!file.is_open()) {
        std::cout << "Can't open config file " << confFile << std::endl;
        return;
    }

    using namespace rapidjson;
    IStreamWrapper isw(file);

    Document doc;
    doc.ParseStream(isw);

    if (!doc.IsObject()) {
        std::cout << "Config is not JSON object: " << std::endl;
        return;
    }

    std::vector<std::string> params;
    params.push_back("log_path");
    params.push_back("server_port");

    for (std::string& param : params) {
        if (doc.HasMember(param.c_str())) {
            if (doc[param.c_str()].IsInt()) {
                m_parameters.emplace(param, std::to_string(doc[param.c_str()].GetInt()));
            } else if (doc[param.c_str()].IsString()){
                m_parameters.emplace(param, doc[param.c_str()].GetString());
            } else if (doc[param.c_str()].IsBool()) {
                if (doc[param.c_str()].GetBool()) {
                    m_parameters.emplace(param, "true");
                } else {
                    m_parameters.emplace(param, "false");
                }
            }
        } else {
            std::cout << "Config has not parameter: " << param << std::endl;
            m_parameters.clear();
            return;
        }
    }
}
