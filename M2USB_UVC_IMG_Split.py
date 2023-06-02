from __future__ import print_function
import time
import codecs
import fnmatch
import os
import re
import struct
import sys

g_UVCFrameFd = str()
g_JPGFd_suffix = 'JPGFolder'
g_UVCFrameFd_suffix = 'UVCFrame'

def RmFileDirByPtn(dirPath, pattern = ""):
    '''
    Remove file, dir by matching pattern (Unix sytle)
    Due to glob.glob not support recursively parser with 2.7 pyhton, here we use os.walk
    '''
    listOfFileDir = []
    listOfFilesWithError = []

    # 1. parser target file, dir recursively, record into listOfFileDir
    if pattern != "":
        for parentDir, dirnames, filenames in os.walk(dirPath):
            if filenames != []:
                for filename in fnmatch.filter(filenames, pattern):
                    listOfFileDir.append(os.path.join(parentDir, filename))

            if dirnames != []:
                for dirname in fnmatch.filter(dirnames, pattern):
                    listOfFileDir.append(os.path.join(parentDir, dirname))
    else:
        listOfFileDir.append(dirPath)

    # 2. remove file, dir by listOfFileDir
    for FileDir in listOfFileDir:
        if os.path.isfile(FileDir):
            try:
                os.remove(FileDir)
            except:
                listOfFilesWithError.append(FileDir)
        elif os.path.isdir(FileDir):
            try:
                shutil.rmtree(FileDir)
            except:
                listOfFilesWithError.append(FileDir)
        else:
            try:
                os.remove(FileDir)
            except:
                listOfFilesWithError.append(FileDir)

    # if listOfFileDir != []:
    #     print("Delete file:")
    #     for FileDir in listOfFileDir:
    #         print(FileDir)

    return listOfFilesWithError

# remove txt file all space
def FileRmAllSpace(In_filename, Out_Filename):
    print("FileRmAllSpace start")
    with open(In_filename, 'r') as in_fp:
        with open(Out_Filename, 'w') as out_fp:
            for line in in_fp:
                line = ''.join(line.split()) # remove all space, tab, newline
                out_fp.write(line)

    print("FileRmAllSpace end")    

# make txt ASCII file into binary file
def AsciiToHexRaw(In_filename, Out_Filename):
    print("FileRmAllSpace start")
    with open(In_filename, 'r') as in_fp:
        with open(Out_Filename, 'wb') as out_raw_fp:
            while(1):
                ch = in_fp.read(2)
                if ch == '': # find file end
                    break

                #print(int(ch, 16)) # string to int base 16 (decode as hex)
                #print(int(ch, 16).to_bytes(2, 'big'))
                out_raw_fp.write((int(ch, 16).to_bytes(1, 'big'))) # int to 1 byte with bit endian

    print("FileRmAllSpace end")

# remove UVC dummy header from binary file
def RmUVCDummyHeader(UVCBin_File):
    # remove 0C 8C 00 00 00 00 00 00 00 00 00 00
    with open(UVCBin_File, 'rb') as in_fp:
        ReadData = in_fp.read()
        with open("Rm0C8C.bin", 'wb') as out_fp:
            pos = 0
            search_pos = 0
            pos_list = []
            while True:    
                pos = ReadData.find(b'\x0C\x8C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', search_pos)
                if pos == -1:
                    break
                else:
                    # print("%d" % pos)
                    pos_list.append(pos)
                    search_pos = pos + 12
            
            if pos_list != []:
                w_begin = 0
                for w_end in pos_list:
                    out_fp.write(ReadData[w_begin:w_end])
                    w_begin = w_end + 12

                out_fp.write(ReadData[w_end:])
            else:
                out_fp.write(ReadData)

    # remove 0C 8D 00 00 00 00 00 00 00 00 00 00
    with open("Rm0C8C.bin", 'rb') as in_fp:
        ReadData = in_fp.read()
        with open("Rm0C8D.bin", 'wb') as out_fp:
            pos = 0
            search_pos = 0
            pos_list = []
            while True:    
                pos = ReadData.find(b'\x0C\x8D\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', search_pos)
                if pos == -1:
                    break
                else:
                    # print("%d" % pos)
                    pos_list.append(pos)
                    search_pos = pos + 12
            
            if pos_list != []:
                w_begin = 0
                for w_end in pos_list:
                    out_fp.write(ReadData[w_begin:w_end])
                    w_begin = w_end + 12

                out_fp.write(ReadData[w_end:])
            else:
                out_fp.write(ReadData)

    # del Rm0C8C.bin
    os.remove("Rm0C8C.bin")
    new_name = os.path.splitext(UVCBin_File)[0] + "_RmUVCDummy.bin"
    try:
        os.remove(new_name)  # del previous old file
    except OSError as exception:
        pass

    os.rename("Rm0C8D.bin", new_name)
    return new_name

# fine all string position in str buffer, return [in_str, position] list
def FindAllStrPos(in_strbuf, in_str, str_len):
    find_pos = 0
    search_pos = 0
    tmp_list = []
    # fine 0C8C
    while True:
        find_pos = in_strbuf.find(in_str, search_pos)
        if find_pos == -1:
            break
        else:
            # print("%d" % find_pos)
            tmp_list.append([in_str, find_pos])
            search_pos = find_pos + str_len
    
    return tmp_list

""" 
這個Tool 分析USB analyzer log解出Jpeg, 可以接受txt或是binary file格式

以下是tool的判斷行為
1.  USB analyzer log對於short pkg不會在後面補上dummy使其對齊3KB, 所以只能透過分析UVC frame idx猜測short pkg出現時機
    若無預警的short pkg則判斷失敗
2.  UVC Frame idx這邊只判斷0C8C, 0C8D, 0C8E, 0C8F, 至於error bit出現時的0CCC, 0CCD, 0CCE, 0CCF 尚未判斷
3.  連續的0C8C, 0C8D UVC Frame idx出現, 可以預期間隔3KB
4.  0C8E, 0C8F出現代表當前UVC frame為short pkg, 距離下個frame idx必小於3KB
    4.1 Jpeg data中也有機會出現0C8C, 0C8D, 會導致我們誤判正確的0C8C, 0C8D出現位置, 尤其是short pkg出現, 連3KB規則都被打破
        這邊我們多做一個判斷, 確認0C8E, 0C8F 與下一個0C8C, 0C8D中間是否有FFD9 (JPEG EOF結尾), 
        如果沒有, 表示這個0C8C, 0C8D是誤判, 則繼續往下搜尋
5.  USB enqueue fail, 會使USB frame idx順序不如預期, 如果enqueue fail剛好出現在0C8E, 0C8F, 可能導致tool部分解析失敗

USB Host可以知道每個UVC Frame的size(USB HW提供資訊), 所以可以準確判斷UVC frame idx位置。
但是站在Parser角度則無法, 這邊只能盡量判斷出UVC idx位置
"""
def UVC_IMG_Split(In_filename):
    print("UVC_IMG_Split start")
    start_time = time.perf_counter()
    # Must add "global" declare if using global var in function, otherwise it will create new local var with the same name
    global g_UVCFrameFd

    In_filenameNoExt = os.path.splitext(In_filename)[0]
    g_UVCFrameFd = In_filenameNoExt + "_" + g_UVCFrameFd_suffix
    
    # file extension is not .bin, means not binary file
    if os.path.splitext(In_filename)[1] != ".bin":
        NoSpace_Filename = In_filenameNoExt + "_NoSpace.txt"
        UVCBin_File = In_filenameNoExt + ".bin"
        FileRmAllSpace(In_filename, NoSpace_Filename)
        AsciiToHexRaw(NoSpace_Filename, UVCBin_File)
    else:   # file is binary file
        UVCBin_File = In_filename

    UVCBin_RmUVCDummy_File = RmUVCDummyHeader(UVCBin_File)
    
    UVC_Frame_list = []

    with open(UVCBin_RmUVCDummy_File, 'rb') as in_fp:
        ReadData = in_fp.read() # search data per UVCFrameSize byte

        tmp_list = FindAllStrPos(ReadData, b'\x0C\x8C', 2)
        UVC_Frame_list.extend(tmp_list)
        tmp_list = FindAllStrPos(ReadData, b'\x0C\x8D', 2)
        UVC_Frame_list.extend(tmp_list)
        tmp_list = FindAllStrPos(ReadData, b'\x0C\x8E', 2)
        UVC_Frame_list.extend(tmp_list)
        tmp_list = FindAllStrPos(ReadData, b'\x0C\x8F', 2)
        UVC_Frame_list.extend(tmp_list)

    # for x in UVC_Frame_list:
    #     print(x)
    print("befor sorting, elapse time: %f" % (time.perf_counter() - start_time))
    UVC_Frame_list.sort(key = lambda UVC_FrameItem : UVC_FrameItem[1]) # sort index by index item (Pos data)
    print("after sorting, elapse time: %f" % (time.perf_counter() - start_time))

    # with open("tmp.txt", 'w') as in_fp:
    #     for x in UVC_Frame_list:
    #         in_fp.write("%s, %d\n" % (x[0], x[1]))

    # Remove unmatch UVC idx in UVC_Frame_list (UVC idx need appeaer every 3KB except 0C8E, 0CEF)
    # If there have unmatch UVC following 0C8E, 0C8F, we can't find it!
    print("Remove unmatch UVC idx start")
    x = 0
    y = 1
    ErrUVCIdx_Find = 0
    ErrUVCIdx_FindCnt = 0
    listNum = len(UVC_Frame_list)
    DelList = []
    with open(UVCBin_RmUVCDummy_File, 'rb') as in_fp:
        ReadData = in_fp.read() # search data per UVCFrameSize byte

        while x < listNum - 1 and y < listNum:
            if UVC_Frame_list[x][0] == b'\x0C\x8C' or UVC_Frame_list[x][0] == b'\x0C\x8D':
                if (UVC_Frame_list[y][1] - UVC_Frame_list[x][1]) < 3072:
                    ErrUVCIdx_Find = True
                elif UVC_Frame_list[x][0] == b'\x0C\x8C' and \
                    (UVC_Frame_list[y][0] != b'\x0C\x8C' and UVC_Frame_list[y][0] != b'\x0C\x8E'):
                    ErrUVCIdx_Find = True
                elif UVC_Frame_list[x][0] == b'\x0C\x8D' and \
                    (UVC_Frame_list[y][0] != b'\x0C\x8D' and UVC_Frame_list[y][0] != b'\x0C\x8F'):
                    ErrUVCIdx_Find = True
            else: # 0C8E, 0C8F case, we expect next UVC idx should be 0C8C, 0C8D, not be 0C8E, 0C8F again
                if UVC_Frame_list[x][0] == b'\x0C\x8E' and UVC_Frame_list[y][0] != b'\x0C\x8D':
                    ErrUVCIdx_Find = True
                elif UVC_Frame_list[x][0] == b'\x0C\x8F' and UVC_Frame_list[y][0] != b'\x0C\x8C':
                    ErrUVCIdx_Find = True
                else:
                    beg_pos = UVC_Frame_list[x][1]
                    end_pos = UVC_Frame_list[y][1]
                    # last UVC frame must have FFD9, otherwise the UVC idx is unmatch
                    if ReadData[beg_pos:end_pos].find(b'\xFF\xD9') == -1: 
                        ErrUVCIdx_Find = True

            if ErrUVCIdx_Find == True:
                DelList.append([UVC_Frame_list[y][0], UVC_Frame_list[y][1]])
                y += 1
                ErrUVCIdx_FindCnt += 1
                ErrUVCIdx_Find = False
                continue
            else:
                x += 1
                y += 1
                if ErrUVCIdx_FindCnt > 0:
                    x = y - 1   # if previous UVC idx is err, adjust x pos
                    ErrUVCIdx_FindCnt = 0
                    ErrUVCIdx_Find = False

    for i in DelList:
        UVC_Frame_list.remove(i)

    print("Remove unmatch UVC idx finish")

    # with open("del.txt", 'w') as in_fp:
    #     for x in DelList:
    #         in_fp.write("%s, %d\n" % (x[0], x[1]))

    # with open("tmp2.txt", 'w') as in_fp:
    #     for x in UVC_Frame_list:
    #         in_fp.write("%s, %d\n" % (x[0], x[1]))

    RmFileDirByPtn(g_UVCFrameFd, "*")  # remove all files under UVCFrameFd

    print("Create UVC frame file start")
    FrameIdx = 1
    for UVC_Frame_Cur, UVC_Frame_next in zip(UVC_Frame_list, UVC_Frame_list[1:]):
        # print(UVC_Frame_Cur, UVC_Frame_next)
        # create folder for store splited UVC Frame file
        try:
            os.mkdir(g_UVCFrameFd)
        except OSError as exception:
            pass

        UVCFile = os.path.splitext(UVCBin_File)[0] + '_' + '#%06d' % FrameIdx + '_' + UVC_Frame_Cur[0].hex().upper() + '.bin'
        UVCFilePath = os.path.join(g_UVCFrameFd, UVCFile)
        with open(UVCBin_RmUVCDummy_File, 'rb') as in_fp:
            in_fp.seek(UVC_Frame_Cur[1], os.SEEK_SET)
            filesize = UVC_Frame_next[1] - UVC_Frame_Cur[1]
            if filesize <= 12:
                # print("Skip! Only UVCHeader, no context, Pos: %d", UVC_Frame_Cur[1])
                pass
            else:
                with open(UVCFilePath, 'wb') as out_fp:
                    out_fp.write(in_fp.read(filesize))

        FrameIdx += 1

    print("after FrameIdx examine, elapse time: %f" % (time.perf_counter() - start_time))
    print("total frame number: %d" % len(UVC_Frame_list))

    # Handle last UVC frame
    UVC_Frame_last = UVC_Frame_list[-1]
    try:
        os.mkdir(g_UVCFrameFd) # create folder for store splited UVC Frame file
    except OSError as exception:
        pass

    # splitext for split "filename" and "ext"
    UVCFile = os.path.splitext(UVCBin_File)[0] + '_' + '#%06d' % FrameIdx + '_' + UVC_Frame_last[0].hex().upper() + '.bin'
    UVCFilePath = os.path.join(g_UVCFrameFd, UVCFile)
    with open(UVCBin_File, 'rb') as in_fp:
        with open(UVCFilePath, 'wb') as out_fp:
            in_fp.seek(UVC_Frame_last[1], os.SEEK_SET)
            out_fp.write(in_fp.read())
    FrameIdx += 1

    ## Create append file for check split file if correct
    # AppendFilePath = os.path.join(UVCFrameFd, "TestAppend.bin")  
    # with open(AppendFilePath, 'wb') as out_fp:
    #     for idx in range(1, FrameIdx): # range 1 ~ (FrameIdx-1)
    #         UVCFile = os.path.splitext(UVCBin_File)[0] + '_' + '#%04d' % idx + '.bin'
    #         UVCFilePath = os.path.join(UVCFrameFd, UVCFile)            
    #         with open(UVCFilePath, 'rb') as in_fp:
    #             out_fp.write(in_fp.read())

    print("UVC_IMG_Split End, elapse time: %f" % (time.perf_counter() - start_time))

# parser UVC frame file from given folder, remove the UVC header and append them to make Jpg file.
def ExtractJPG_FromUVCSplitFile(UVCFrameFd):
    print('ExtractJPG_FromUVCSplitFile start')
    start_time = time.perf_counter()
    # Get File Name part by ignore suffix, and compose JPG folder
    suffix_idx = UVCFrameFd.find(g_UVCFrameFd_suffix)
    JPGFd = UVCFrameFd[:suffix_idx-1] + g_JPGFd_suffix

    UVC_SplitFileNameList = os.listdir(UVCFrameFd)
    try:
        os.mkdir(JPGFd) # create folder for store JPG
    except OSError as exception:
        pass

    RmFileDirByPtn(JPGFd, "*")  # remove all files under JPGFd

    re_pattern = re.compile(r"""([^#]+)         # prefix file name
                                \#(\d+)         # UVC Frame idx
                                _([^.]*)        # 0C8C...
                                """, re.X)
    
    IsLastUVCFrame = True # for set first UVCFirstFrameIdx
    UVCFirstFrameIdx = -1
    UVCLastFrameIdx = -1
    JpgIdx = 1
    for UVCFile in UVC_SplitFileNameList:
        s1 = re_pattern.search(UVCFile) # paser UVC frame idx and token for file name
        UVCFilePrefix = s1.group(1)
        UVCFrameIdx = s1.group(2)
        UVCFrameToken = s1.group(3)

        # "split" for split "file path" and "file name"
        JPGFile = os.path.split(UVCFilePrefix)[1] + '#%06d' % JpgIdx + '.jpg'
        JPGFilePath = os.path.join(JPGFd, JPGFile)
        UVCFilePath = os.path.join(UVCFrameFd, UVCFile)

        with open(UVCFilePath, 'rb') as in_fp:
            
            if UVCFrameToken == '0C8C' or UVCFrameToken == '0C8D': # find UVC Frame begin!
                if IsLastUVCFrame == True:
                    UVCFirstFrameIdx = UVCFrameIdx

                IsLastUVCFrame = False
            elif UVCFrameToken == '0C8E' or UVCFrameToken == '0C8F': # find UVC Frame end!
                UVCLastFrameIdx = UVCFrameIdx;
                IsLastUVCFrame = True
            else:
                print("Parser UVCFrameToken fail!")
                return -1

            in_fp.read(12) # skip UVC header 12 bytes
            with open(JPGFilePath, 'ab') as out_fp:
                out_fp.write(in_fp.read())

        if IsLastUVCFrame == True:
            NewJPGFile = os.path.split(UVCFilePrefix)[1] + \
                        '#%06d' % JpgIdx + '_' + '%s-' % UVCFirstFrameIdx + '%s' % UVCLastFrameIdx + '.jpg'
            NewJPGFilePath = os.path.join(JPGFd, NewJPGFile)
            os.rename(JPGFilePath, NewJPGFilePath) # add UVC frame idx information

            JpgIdx += 1 # change Jpg file name

    print("ExtractJPG_FromUVCSplitFile end, elapse time: %f" %  (time.perf_counter() - start_time))

if __name__ == '__main__':
    rst = UVC_IMG_Split(sys.argv[1])
    if rst == -1:
        exit()

    ExtractJPG_FromUVCSplitFile(g_UVCFrameFd)
