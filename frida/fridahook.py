import frida
import sys
import argparse




def on_message(message, data):
    print(message)


def getJSCode(pkgname):
    stJSCode = '''
    Java.perform(function () {
        var dexClassLoader = Java.use('dalvik.system.DexClassLoader');
        dexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(srcDexFp, libFp, libSearchFp, PClassLoader){
            console.log('[*] Frida 开始脱壳');
            console.log('[*] 获取原始DEX文件位置：' + srcDexFp);

            var stDumpFp = "/data/data/''' + pkgname + '''/cache/dump";
            var FileOutputStream = Java.use("java.io.FileOutputStream");
            var FileInputStream = Java.use("java.io.FileInputStream");
            var fin = FileInputStream.$new(srcDexFp);
            var fout = FileOutputStream.$new(stDumpFp);
            
            var btTmp = Java.array('byte', [0x00]);
            var fret = 0;
            while((fret = fin.read(btTmp, 0, 1)) != -1){
                fout.write(btTmp, 0, 1);
            }
            console.log('[*] Dump 原始DEX文件到：' + stDumpFp + ' successful!!');
            return this.$init(srcDexFp, libFp, libSearchFp, PClassLoader)
        };
    });
    '''
    return stJSCode

def unshellapk(pkgname):
    device = frida.get_usb_device()
    pid = device.spawn(pkgname)
    session = device.attach(pid)
    stJSCode = getJSCode(pkgname)
    script = session.create_script(stJSCode)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    sys.stdin.read()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', help="输入需要脱壳的APP包名", metavar='Package NAME')
    args = parser.parse_args()

    if args.p:
        stPkgname = args.__dict__.get('p')
        unshellapk(stPkgname)
    else:
        parser.print_help()
    
    