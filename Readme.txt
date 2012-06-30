ZDClient v1.1 Readme

安装：
    在安装前，请用户先编辑运行脚本文件runzdclient，将其中的user和pass分别修改成您的帐号和密码并保存。 

    安装需要root权限，这通常使用sudo或者su -c

    sudo ./install 

    安装程序会复制核心程序zdclient以及用户脚本runzdclient到系统目录/usr/bin，并设置相关属性，如果用户希望安装到其他目录，可给出目的路径，如sudo ./install /usr/local/bin，但请保证目的目录在系统PATH环境变量内。 

    成功执行安装将看到####Installation Done.####的提示。 

运行：
	
    如果用户配置的帐号信息无误并且安装成功，那么用户只需要运行runzdclient，即可看到有关的认证成功的信息。 

    如果系统内安装有libnotify的工具，运行脚本时会出现如图的提示(Ubuntu中的效果，如果没有，请安装sudo apt-get libnotify-bin):[没有安装libnotify-bin虽然不能显示，但并不影响认证。]

    可以通过桌面的启动器运行runzdclient，或把把runzdclient加入到比如GNOME的“系统->首选项->启动程序“当中，以便每次登录系统即可自动认证上网。 

终止：
    用户执行一次`runzdclient -l`，即可成功离线。 

编译：
    用户可通过svn获得最新的开发代码：

    svn checkout http://zdcclient.googlecode.com/svn/trunk/ zdcclient-read-only  

    或者从项目主页下载版本代码包并自行解压。 

        http://code.google.com/p/zdcclient/downloads/list

    编译需要libpcap库，一般Linux发行版里面安装libpcap包即可，在ubuntu中，需要libpcap-dev：

        sudo apt-get install libpcap-dev

    从命令行进入源代码目录，运行make，应该很快就能生成zdclient，当然前提是系统中安装了gcc等编译环境，这里不再累赘。 

    make install也可完成安装，这根运行install效果基本一样，同样有make uninstall以供卸载。再次提醒安装前先修改runzdclient文件内的账户信息。 

    MacOS / BSD 用户编译：

    Mac用户首先要安装gcc，需要从http://connect.apple.com/下载安装Xcode Tools，具体请查阅Apple Dev的信息。然后下载libpcap的源代码，http://www.tcpdump.org/release/libpcap-1.0.0.tar.gz，解压后分别运行
    ./configure
    make 
    sudo make install

    最后在本程序的源代码目录运行

    make -f Makefile.bsd

    即可生成可运行程序。安装运行参考上文Linux部分。

其他

    当用户使用的认证网卡不是默认的第一个网卡（如eth0）时，可使用runzdclient --dev eth1这样的参数方式启动程序，或者修改runzdclient文件内ARGS=""，加入自定义的参数。 

DHCP模式：
    
    当认证环境需要使用DHCP模式时，需要使用--dhcp参数启动(可在runzdclient的#其他参数行设定)
    
	这里提到的DHCP模式不是完全指网卡是否用DHCP获取IP，DHCP模式的特点是：
	1.在Windows启动后，提示本地连接受限，网卡IP为169.254.x.x的格式，使用客户端认证后才重新获取IP；
	2.在Linux下启动后，网卡IP为空；
	如果符合以上两点，则必须使用--dhcp模式启动zdclient，而且在认证成功后，是需要运行系统的DHCP客户端重新获取一次IP的，通常是dhclient，这一点在启动脚本dhcp_zdc_run.sh内已经包含。
	
	至于在认证前已经能获得IP的环境，不是这里所说的动态模式，使用静态模式启动即可。

版本号：
	认证报文中包含了协议版本号，zdclient 0.4版中的默认版本号是以武汉大学官方客户端的3.5.04.1013fk为准，已知更新的版本是3.5.04.1110fk，不过暂时不影响使用。如果您使用时发现提示&&Info: Invalid Username or Client info mismatch.，很可能是软件的版本号和您使用环境的认证系统不匹配，可尝试使用--ver参数自定义版本号，或联系作者PT，帮助ZDClient兼容您的环境。
	
	

A PT Work. 

项目主页： http://code.google.com/p/zdcclient/
Blog:    http://apt-blog.co.cc
GMail:   pentie@gmail.com

2009-05-20 于广州大学城
