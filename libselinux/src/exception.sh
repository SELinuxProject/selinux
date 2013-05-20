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
     return NULL;
  }
}
"
;;
esac
}
gcc -x c -c -I../include - -aux-info temp.aux < ../include/selinux/selinux.h
for i in `awk '/<stdin>.*extern int/ { print $6 }' temp.aux`; do except $i ; done 
rm -f -- temp.aux -.o
