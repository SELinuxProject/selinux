function except() {
case $1 in
    selinux_file_context_cmp) # ignore
    ;;
    *)
echo "
%exception $1 {
  \$action 
  if (result < 0) {
     PyErr_SetFromErrno(PyExc_OSError);
     SWIG_fail;
  }
}
"
;;
esac
}
if ! ${CC:-gcc} -x c -c -I../include - -aux-info temp.aux < ../include/selinux/selinux.h
then
    # clang does not support -aux-info so fall back to gcc
    gcc -x c -c -I../include - -aux-info temp.aux < ../include/selinux/selinux.h
fi
for i in `awk '/<stdin>.*extern int/ { print $6 }' temp.aux`; do except $i ; done 
rm -f -- temp.aux -.o
