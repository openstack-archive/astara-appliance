This element requires that you have already downloaded a crt and key file from
nginx.

Download nginx-repo.crt and nginx-repo.key into any directory. Then when
executing set DIB_NGINX_PLUS_CERT_PATH to that directory.

i.e.

  ELEMENTS_PATH=diskimage-builder/elements DIB_RELEASE=wheezy DIB_EXTLINUX=1 DIB_NGINX_PLUS_CERT_PATH=/home/david/nginxcerts \
  disk-image-create debian vm nginx-plus -o nginxplus
