from ua_parser import user_agent_parser
import re


class UserAgentChecker:
    UC_BROWSER = "UC Browser"
    SAFARI_REGX = "Safari"
    CHROME_REGX = "Chrom(e|ium)"
    MAC_OSX = "Mac OS X"
    IOS = "iOS"
    MIN_UC_BROWSER_VER_MAJOR = 12
    MIN_UC_BROWSER_VER_MINOR = 13
    MIN_UC_BROWSER_VER_BUILD = 2
    BUGGY_CHROME_VERSION_MAJOR_MIN = 51
    BUGGY_CHROME_VERSION_MAJOR_MAX = 66
    MIN_IOS_VERSION = 12
    MIN_MAC_OSX_VERSION_MAJOR = 10
    MIN_MAC_OSX_VERSION_MINOR = 14

    def __init__(self, user_agent_string=""):
        user_agent_parsed = user_agent_parser.Parse(
            user_agent_string if user_agent_string else ""
        )
        self.user_agent = user_agent_parsed.get("user_agent", dict())
        self.user_agent_os = user_agent_parsed.get("os", dict())
        self.user_agent_device = user_agent_parsed.get("device", dict())
        self.user_agent_string = user_agent_parsed.get("string", "")
        self.user_agent_family = user_agent_parsed.get("family", "")

    @property
    def is_ie(self):
        return self.user_agent_family == "IE"

    @property
    def do_not_send_same_site_policy(self):
        if not self.user_agent_string:
            return False
        else:
            return not (self.supported_browsers_os() or self.other_browsers())

    def supported_browsers_os(self):
        return (
            self.supported_ios_and_mac_os_browsers()
            or self.supported_chrome_and_uc_browsers()
        )

    def supported_chrome_and_uc_browsers(self):
        return (
            self.is_chrome_supported_version()
            or self.is_uc_browser_in_least_supported_version()
        )

    def supported_ios_and_mac_os_browsers(self):
        return self.is_supported_ios_version() or self.is_supported_mac_osx_safari()

    def other_browsers(self):
        is_uc_or_chrome = self.is_uc_browser() or self.is_chrome_browser()
        is_safari_ios_mac_supported = (
            self.is_safari() or self.is_ios() or self.is_supported_mac_osx_safari()
        )
        return not (is_uc_or_chrome or is_safari_ios_mac_supported)

    def is_uc_browser(self):
        return self.user_agent.get("family") == "UC Browser"

    def is_uc_browser_in_least_supported_version(self):
        major = self.get_val_in_int(self.user_agent.get("major"))
        minor = self.get_val_in_int(self.user_agent.get("minor"))
        build = self.get_val_in_int(self.user_agent.get("patch"))
        if self.is_uc_browser():
            if self.MIN_UC_BROWSER_VER_MAJOR == major:
                if self.MIN_UC_BROWSER_VER_MINOR == minor:
                    return self.MIN_UC_BROWSER_VER_BUILD <= build
                else:
                    return self.MIN_UC_BROWSER_VER_MINOR < minor
            else:
                return self.MIN_UC_BROWSER_VER_MAJOR < major
        return False

    def is_chrome_browser(self):
        return (
            True
            if re.search(self.CHROME_REGX, self.user_agent.get("family", ""))
            else False
        )

    def is_chrome_supported_version(self):
        uav = self.get_val_in_int(self.user_agent.get("major"))
        return (
            True
            if self.is_chrome_browser()
            and (
                self.BUGGY_CHROME_VERSION_MAJOR_MIN > uav
                or uav > self.BUGGY_CHROME_VERSION_MAJOR_MAX
            )
            else False
        )

    def get_user_agent_os_version(self, version_type):
        return self.get_val_in_int(self.user_agent_os.get(version_type))

    def get_user_agent_os_major(self):
        return self.get_user_agent_os_version("major")

    def get_user_agent_os_minor(self):
        return self.get_user_agent_os_version("minor")

    def get_val_in_int(self, val):
        try:
            return int(val or "0")
        except (TypeError, ValueError):
            return 0

    def is_ios(self):
        return self.user_agent_os.get("family") == self.IOS

    def is_supported_ios_version(self):
        return self.is_ios() and not (
            self.get_user_agent_os_major() == self.MIN_IOS_VERSION
        )

    def is_mac_osx(self):
        return self.user_agent_os.get("family", "") == self.MAC_OSX

    def is_supported_mac_osx_version(self):
        if self.is_mac_osx():
            is_min_mac_maj = (
                self.get_user_agent_os_major() == self.MIN_MAC_OSX_VERSION_MAJOR
            )
            is_min_mac_min = (
                self.get_user_agent_os_minor() == self.MIN_MAC_OSX_VERSION_MINOR
            )
            return not (is_min_mac_maj and is_min_mac_min)
        return False

    def is_safari(self):
        is_safari_reg_res = re.search(
            self.SAFARI_REGX, self.user_agent.get("family", "")
        )
        return True if is_safari_reg_res and not self.is_chrome_browser() else False

    def is_supported_mac_osx_safari(self):
        return self.is_supported_mac_osx_version() and self.is_safari()
