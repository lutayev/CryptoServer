#ifndef CONFIGCONTROLLER_H
#define CONFIGCONTROLLER_H

#include <string>
#include <map>
#include <stdexcept>

class ConfigController
{
public:
    ConfigController() = delete;
    ConfigController(ConfigController& other) = delete;

    template<class T>
    static T getValue(const std::string&);
private:

    static void init();
    static std::map<std::string, std::string> m_parameters;
};


//Template member, placed in header
template <class T>
T ConfigController::getValue(const std::string &parameter)
{
    T res;
    if (ConfigController::m_parameters.empty()) {
        ConfigController::init();
    }
    std::string value;
    auto it = ConfigController::m_parameters.find(parameter);

    if(it != ConfigController::m_parameters.end()) {
        value = it->second;
    }

    if (std::is_same<T, int>::value) {
        int tmp = std::stoi(value);
        res = *reinterpret_cast<T*>(&tmp);
    } else if (std::is_same<T, std::string>::value) {
        res = *reinterpret_cast<T*>(&value);
    } else if (std::is_same<T, bool>::value) {
        bool tmp = (value == "true" ? true : false);
        res = *reinterpret_cast<T*>(&tmp);
    } else {
        throw std::runtime_error("Invalid/unsupported parameter type");
    }

    return res;
}

#endif // CONFIGCONTROLLER_H
