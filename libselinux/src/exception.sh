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
echo '#include "../include/selinux/selinux.h"' > temp.c
gcc -c temp.c -aux-info temp.aux 
for i in `awk '/..\/include\/selinux\/selinux.h.*extern int/ { print $6 }' temp.aux`; do except $i ; done 
rm -f temp.c temp.aux temp.o
