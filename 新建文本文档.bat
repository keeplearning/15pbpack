@echo off
@echo 注意,本程序会删除当前文件夹下的所有exe文件, 如果想退出,点击右上角的关闭按钮还来得及
color a
pause
del /s  *.ilk *.pdb *.obj *.log *.pch *.tlog *.lastbuildstate *.sdf *.idb *.ipch *.res *.o *.lst *.knl *.img *.bin *.db *.exe
@echo 清理完成
pause
