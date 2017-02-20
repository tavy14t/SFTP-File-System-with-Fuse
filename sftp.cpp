#define FUSE_USE_VERSION 26
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <fuse.h>
#include <stddef.h>
#include <assert.h>
#include <fcntl.h>
#include <vector>
#include <string>
#include <queue>
// #define DEBUG
using namespace std;


// ------------------------------- FILE ----------------------------------------
class File
{
	public:
		LIBSSH2_SFTP_ATTRIBUTES attrs;
		// 	{
		//      unsigned long flags;
		//      libssh2_uint64_t filesize;
		//      unsigned long uid, gid;
		//      unsigned long permissions;
		//      unsigned long atime, mtime;
 		// 	};
		string 					path;
		File()
		{
			memset(this, 0, sizeof(this));
		}
		File(char* path, LIBSSH2_SFTP_ATTRIBUTES attrs)
		{
			this->path.assign(path, strlen(path));
			this->attrs = attrs;
		}
		bool IsDir()
		{
			if(LIBSSH2_SFTP_S_ISDIR(attrs.permissions))
				return true;
			return false;
		}
		bool IsFile()
		{
			if(LIBSSH2_SFTP_S_ISREG(attrs.permissions))
				return true;
			return false;
		}
		bool IsFIFO()
		{
			if(LIBSSH2_SFTP_S_ISFIFO(attrs.permissions))
				return true;
			return false;
		}
		bool IsSOCK()
		{
			if(LIBSSH2_SFTP_S_ISSOCK(attrs.permissions))
				return true;
			return false;
		}
		bool IsBlock()
		{
			if(LIBSSH2_SFTP_S_ISBLK(attrs.permissions))
				return true;
			return false;
		}
		bool IsSpecialCharacterFile()
		{
			if(LIBSSH2_SFTP_S_ISCHR(attrs.permissions))
				return true;
			return false;
		}
		bool IsLink()
		{
			if(LIBSSH2_SFTP_S_ISLNK(attrs.permissions))
				return true;
			return false;
		}
		unsigned long long GetSize()
		{
			return attrs.filesize;
		}
		unsigned GetPermissions()
		{
			return attrs.permissions;
		}
		unsigned GetLastModifiedTime()
		{
			return attrs.mtime;
		}
		unsigned GetLastAccessTime()
		{
			return attrs.atime;
		}
		unsigned GetUID()
		{
			return attrs.uid;
		}
		unsigned GetGID()
		{
			return attrs.gid;
		}
		unsigned GetFlags()
		{
			return attrs.flags;
		}
};


// ----------------------------- SERVER ----------------------------------------
class Server
{
	private:
		struct hostent 		*address;
		struct sockaddr_in 	socketaddressin;
		int 				socketdescriptor;
		int 				port;
		const char			*fingerprint;
		char				*userauthlist;
		char				username[256];
		char				*password;
		char 				remotepath[2048];
		char 				mountpoint[2048];
		LIBSSH2_SESSION		*session;
		LIBSSH2_SFTP 		*sftp_session;
		LIBSSH2_SFTP_HANDLE *file_handle;
		LIBSSH2_CHANNEL		*channel;
		void PrintCredentials()
		{
			#ifdef DEBUG
				if (username[0] == '\0')
					fprintf(stdout, "username: N/A\n");
				else
					fprintf(stdout, "username: %s\n", username);

				if (password[0] == '\0')
					fprintf(stdout, "password: N/A\n");
				else
					fprintf(stdout, "password: %s\n", password);
			#endif
		}
	public:
		Server()
		{
			memset(this, 0, sizeof(Server));
		}
		void SetUsername(char *user)
		{
			strcpy(username, user);
		}
		void ReadCredentials()
		{
			#ifdef DEBUG
				strcpy(username, "your.username.here");
				password = (char*) "your.pass.here";
			#else
				if(username[0] == '\0')
				{
					fprintf(stdout, "Username: ");
					fgets(username, sizeof(username), stdin);
					((char*)strchr(username, '\n'))[0] = 0;
				}
				this->password = getpass("Password: ");
			#endif
		}	
		void InitServerConnection()
		{
			socketaddressin.sin_family 	= AF_INET;
			socketaddressin.sin_port	= this->port;
			socketaddressin.sin_addr	= *(in_addr*)this->address->h_addr;
			socketaddressin.sin_port	= htons(port);

			if((this->socketdescriptor = socket(AF_INET, SOCK_STREAM, 0)) == -1)
			{
				fprintf(stderr, "Could not create socket!\n");
				exit(1);
			}
			if(connect(socketdescriptor, (struct sockaddr*)&socketaddressin, 
				sizeof(struct sockaddr)) == -1)
			{
				fprintf(stderr, "Could not connect to server!\n");
				exit(1);
			}
			fprintf(stdout, "Connection established!\n");
		}
		void InitSSHConnection()
		{	
			int rc; // return code
			if((rc = libssh2_init(0)) != 0)
			{
				fprintf(stderr, "libssh2 initialization failed (%d)!\n", rc);
				exit(1);
			}

			if((this->session = libssh2_session_init()) == NULL)
			{
				fprintf(stderr, "libssh2 sessiion initialization failed!\n");
				exit(1);
			}
			libssh2_session_set_blocking(this->session, 1);
			if((rc = libssh2_session_handshake(
				this->session, this->socketdescriptor)) != 0)
			{
				fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
				exit(1);
			}

			this->fingerprint = libssh2_hostkey_hash(session, 
								LIBSSH2_HOSTKEY_HASH_SHA1); // or MD5 at end
		}
		void CloseServerConnection()
		{
			if(session)
			{
				libssh2_session_disconnect(session, "Shutting down session!");
				libssh2_session_free(session);
			}
			close(socketdescriptor);
			libssh2_exit();
		}
		void SetPort(int port)
		{
			if(port <= 0 || port >= 65536)
			{
				fprintf(stderr, "Invalid port!\n");
				exit(1);
			}
			this->port = port;
		}
		void SetPort(char* port)
		{
			this->SetPort(atoi(port));
		}
		void PrintVars()
		{
			fprintf(stdout, "port: %d\n", this->port);
			fprintf(stdout, "remotepath: %s\n", this->remotepath);
			fprintf(stdout, "mountpoint: %s\n", this->mountpoint);
			this->PrintHostent();
			this->PrintFingerprint();
			this->PrintCredentials();
		}
		void PrintFingerprint()
		{
			if(this->fingerprint == NULL)
			{
				fprintf(stdout, "fingerprint: N/A\n");
				return;
			}

			fprintf(stdout, "Fingerprint: ");
			for(int i=0; i < 20; i++)
				fprintf(stdout, "%02X ", (unsigned char) fingerprint[i]);
			fprintf(stdout, "\n");
		}
		void SetAddress(struct hostent *address)
		{
			this->address = address;
		}
		void PrintHostent()
		{
			if(this->address == NULL)
			{
				fprintf(stdout, "hostent structure: N/A\n");
				return;
			}
			fprintf(stdout, "hostent structure:\n");
			fprintf(stdout, "	h_name = %s\n", address->h_name);
			for(int i = 0; address->h_aliases[i] != NULL; i++)
				fprintf(stdout, "	h_aliases[%d] = %s\n", i, 
					inet_ntoa(*(in_addr*)address->h_aliases[i]));

			fprintf(stdout, "	h_addrtype = %d\n", address->h_addrtype);
			fprintf(stdout, "	h_length = %d\n", address->h_length);

			for(int i = 0; address->h_addr_list[i] != NULL; i++)
				fprintf(stdout, "	h_addr_list[%d] = %s\n", i, 
					inet_ntoa(*(in_addr*)address->h_addr_list[i]));

			fprintf(stdout, "	h_addr = %s\n", 
				inet_ntoa(*(in_addr*)address->h_addr));
		}
		void SSHAuth()
		{
			if(libssh2_userauth_password(session, username, password))
			{
				fprintf(stderr, "Authentication by password failed.\n");
				this->CloseServerConnection();
				exit(1);
			}
			fprintf(stdout, "SSH Authentication succeed!\n");
		}
		void InitRemotePath()
		{
			channel = libssh2_channel_open_session(session);
			if(channel == NULL)
			{
				fprintf(stderr, "Could not create SSH channel!\n");
				exit(1);
			}
			fprintf(stdout, "SSH channel created!\n");

			libssh2_channel_exec(channel, "pwd");
			libssh2_channel_read(channel, remotepath, sizeof(remotepath));
			libssh2_channel_close(channel);
			libssh2_channel_free(channel);
			
			if(remotepath[0] == '\0')
				strcpy(remotepath, "/");
			else
				remotepath[strlen(remotepath) - 1] = '/';
		}
		char* GetRemotePath()
		{
			return this->remotepath;
		}
		void InitSFTPSession()
		{
			this->sftp_session = libssh2_sftp_init(session);
			if (sftp_session == NULL)
			{
				fprintf(stderr, "Unable to init SFTP session!\n");
				this->CloseServerConnection();
				exit(1);
			}
			fprintf(stdout, "SFTP session init succeed!\n");
		}
		vector<File*>* GetFilesFromDir(char *path, bool recursive = false)
		{
			vector<File*> *items = new vector<File*>();
			int rc;

			LIBSSH2_SFTP_HANDLE *sftp_handle_local = 
				libssh2_sftp_opendir(sftp_session, path);

			if (sftp_handle_local == NULL) 
			{
				fprintf(stderr, "Unable to open dir with SFTP\n");
				return items;
			}

			do
			{
				char mem[1024];
				char longentry[1024];
				LIBSSH2_SFTP_ATTRIBUTES attrs;

				rc = libssh2_sftp_readdir_ex(sftp_handle_local, 
					mem, sizeof(mem),
					longentry, sizeof(longentry), &attrs);

				if(rc > 0)
				{
					if(!strcmp(mem, "..") || !strcmp(mem, "."))
						continue;

					items->push_back(new File(mem, attrs));
				}
				else
					break;
			}while(1);

			libssh2_sftp_closedir(sftp_handle_local);
			return items;
		}
		void SetMountPoint(char *path)
		{
			struct stat statbuf;
			stat(path, &statbuf);
			if(!S_ISDIR(statbuf.st_mode))
			{
				fprintf(stderr, "Invalid mountpoint!\n");
				exit(1);
			}
			strcpy(this->mountpoint, path);
		}
		char* GetMountPoint()
		{
			if(this->mountpoint[0] == '\0')
			{
				printf("Invalid mountpoint! Using: /mnt/fuse/\n");
				strcpy(this->mountpoint, "/mnt/fuse/");
			}
			return this->mountpoint;
		}
		File* GetFile(const char *path, int &ret_code)
		{
			File* f = new File();
			f->path = path;
			ret_code = libssh2_sftp_stat(sftp_session, path, &f->attrs);

			#ifdef DEBUG
			printf("[SFTP_LOG][%s] {'path':'%s', ret_code: %d}\n",
				__FUNCTION__, path, ret_code);

			if(ret_code == LIBSSH2_ERROR_ALLOC)
				fprintf(stderr, "[SFTP_LOG][%s] An internal memory"
					" allocation call failed.\n", __FUNCTION__);
			else if(ret_code == LIBSSH2_ERROR_SOCKET_SEND)
				fprintf(stderr, "[SFTP_LOG][%s]"
					" Unable to send data on socket.\n", __FUNCTION__);
			else if(ret_code == LIBSSH2_ERROR_SOCKET_TIMEOUT)
				fprintf(stderr, "[SFTP_LOG][%s]"
					" Socket timeout error.\n", __FUNCTION__);
			else if(ret_code == LIBSSH2_ERROR_SFTP_PROTOCOL)
				fprintf(stderr, "[SFTP_LOG][%s] An invalid SFTP protocol"
					" response was received on the socket\n", __FUNCTION__);
			else if(ret_code == LIBSSH2_ERROR_EAGAIN)
				fprintf(stderr, "[SFTP_LOG][%s] ERROR_EAGAIN", __FUNCTION__);		
			#endif

			return f;
		}
		size_t ReadFile(const char *path, char *buf, size_t size, off_t offset)
		{
			off_t buffer_offset = 0;

			file_handle = libssh2_sftp_open_ex(
				sftp_session, path, strlen(path),
				LIBSSH2_FXF_READ, LIBSSH2_SFTP_S_IRWXU, LIBSSH2_SFTP_OPENFILE);

			if(file_handle == NULL)
			{
				fprintf(stderr, "Could not create handle to: %s\n", path);
				return 0;
			}

			libssh2_sftp_seek64(file_handle, offset);

			while(1)
			{
				size_t bytes_read = libssh2_sftp_read(file_handle,
					buf + buffer_offset, size);
				buffer_offset += bytes_read;
				size -= bytes_read;

				#ifdef DEBUG
				fprintf(stdout, "[SFTP_LOG][%s]"
					" {'b_read':%lu,'buf_off':%lu,'remained':%lu}\n",
					__FUNCTION__, bytes_read, buffer_offset, size);
				#endif

				if(bytes_read <= 0)
					break;
			}

			libssh2_sftp_close(file_handle);

			return buffer_offset;
		}
		int CreateDirectory(const char *path, mode_t mode)
		{
			return libssh2_sftp_mkdir(sftp_session, path, mode);
		}
		int WriteFile(const char *path, const char *buffer,
			size_t size, off_t offset)
		{
			off_t buffer_offset = 0;

			file_handle = libssh2_sftp_open_ex(
				sftp_session, path, strlen(path),
				LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT,
				LIBSSH2_SFTP_S_IRWXU, LIBSSH2_SFTP_OPENFILE);

			if(file_handle == NULL)
			{
				fprintf(stderr, "Could not create handle to: %s\n", path);
				return 0;
			}

			libssh2_sftp_seek64(file_handle, offset);

			while(1)
			{
				size_t bytes_written = libssh2_sftp_write(file_handle, 
					buffer + buffer_offset, size);
				buffer_offset += bytes_written;
				size -= bytes_written;

				#ifdef DEBUG
				fprintf(stdout, "[SFTP_LOG][%s]"
					" {'b_written':%lu,'buf_off':%lu,'remained':%lu}\n",
					__FUNCTION__, bytes_written, buffer_offset, size);
				#endif

				if(bytes_written <= 0)
					break;
			}

			libssh2_sftp_close(file_handle);

			return buffer_offset;
		}
		int CreateFile(const char *path, mode_t mode)
		{
			#ifdef DEBUG
			fprintf(stdout, "[SFTP_LOG][%s]"
					" {'path':'%s','mode':%d}\n",
					__FUNCTION__, path, mode);
			#endif

			file_handle = libssh2_sftp_open_ex(
				sftp_session, path, strlen(path),
				LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC,
				LIBSSH2_SFTP_S_IRWXU, LIBSSH2_SFTP_OPENFILE);

			LIBSSH2_SFTP_ATTRIBUTES *attrs = new LIBSSH2_SFTP_ATTRIBUTES();
			attrs->flags  = LIBSSH2_SFTP_ATTR_PERMISSIONS;
			attrs->flags |= LIBSSH2_SFTP_ATTR_ACMODTIME;
			attrs->flags |= LIBSSH2_SFTP_ATTR_SIZE;

			attrs->filesize 	= 0;
			attrs->permissions 	= mode;
			attrs->atime 		= (unsigned long)	time(NULL);
			attrs->mtime 		= (unsigned long)	time(NULL);

			libssh2_sftp_fstat_ex(file_handle, attrs, 1);

			if(file_handle == NULL)
			{
				fprintf(stderr, "Could not create file: %s\n", path);
				return -1;
			}
			libssh2_sftp_close(file_handle);
			return 0;
		}
		int DeleteFile(const char *path)
		{
			int ret_code;
			ret_code = libssh2_sftp_unlink(sftp_session, path);

			#ifdef DEBUG
			fprintf(stdout, "[SFTP_LOG][%s] {'path':'%s',ret_code: %d}\n",
				__FUNCTION__, path, ret_code);
			#endif

			return ret_code;
		}
		int SetAttributes()
		{
			return 0;
		}
		int ChangeOwnership(const char *path, uid_t owner, gid_t group)
		{
			fprintf(stdout, "[SFTP_LOG][%s]"
					" {'owner':'%d','group':%d}\n",
					__FUNCTION__, owner, group);

			file_handle = libssh2_sftp_open_ex(
				sftp_session, path, strlen(path),
				LIBSSH2_FXF_CREAT, LIBSSH2_SFTP_S_IRWXU,
				LIBSSH2_SFTP_OPENFILE);

			int ret_code;
			File* old_file = GetFile(path, ret_code);

			old_file->attrs.uid = owner;
			old_file->attrs.gid = group;

			libssh2_sftp_fstat_ex(file_handle, &old_file->attrs, 1);
			
			if(ret_code != 0)
				return -1;

			return 0;
		}
		int ChangePermissions(const char *path, mode_t mode)
		{
			#ifdef DEBUG
			fprintf(stdout, "[SFTP_LOG][%s]"
					" {'path':'%s','mode':%d}\n",
					__FUNCTION__, path, mode);
			#endif

			file_handle = libssh2_sftp_open_ex(
				sftp_session, path, strlen(path),
				LIBSSH2_FXF_CREAT, LIBSSH2_SFTP_S_IRWXU,
				LIBSSH2_SFTP_OPENFILE);

			int ret_code;
			File* old_file = GetFile(path, ret_code);

			old_file->attrs.permissions = mode;

			libssh2_sftp_fstat_ex(file_handle, &old_file->attrs, 1);
			
			if(ret_code != 0)
				return -1;

			return 0;
		}
		int DeleteDirectory(const char *path)
		{
			return libssh2_sftp_rmdir(sftp_session, path);
		}
};



///// --------------------------------FUSE--------------------------------------
class Fuse
{
	private:
		static int 				remotepath_length;
		static Server 			*server;
		static vector<File*> 	*files;
		static struct fuse_operations 	operations;
		static struct fuse_args 		args;

		static int sftp_chmod(const char *path, mode_t mode)
		{
			char *remotefile = join_paths(server->GetRemotePath(), path);
			return Fuse::server->ChangePermissions(remotefile, mode);
		}
		static int sftp_unlink(const char *path)
		{
			char *remotefile = join_paths(server->GetRemotePath(), path);
			return Fuse::server->DeleteFile(remotefile);
		}
		static int sftp_setattr(const char *path, const char *name, const char *value, size_t size, int flags)
		{	
			// useless function. chmod and chown replaces this
			// printf("%s : %s %s %lu %d\n", __FUNCTION__, path, name, value, size, flags);
			return 0;
		}
		static int sftp_mknod(const char *path, mode_t mode, dev_t rdev)
		{
			#ifdef DEBUG
			fprintf(stdout, "[SFTP_LOG][%s]"
				" {'path':%s,'mode':%d}\n",
				__FUNCTION__, path, mode);
			#endif

			char *remotefile = join_paths(server->GetRemotePath(), path);
			return Fuse::server->CreateFile(remotefile, mode);
		}
		static int sftp_access(const char*path, int mode)
		{
			char *remotedir = join_paths(server->GetRemotePath(), path);
			int ret_code;
			File* f = Fuse::server->GetFile(remotedir, ret_code);
			return ret_code;
		}
		static int sftp_readdir(const char *path, void *buf,
								fuse_fill_dir_t filler,
								off_t offset, struct fuse_file_info *fi)
		{
			(void) offset;
			(void) fi;

			filler(buf, ".", NULL, 0);
			filler(buf, "..", NULL, 0);

			char *remotedir = join_paths(server->GetRemotePath(), path);

			vector<File*> *files_array = server->GetFilesFromDir(remotedir);

			#ifdef DEBUG
			fprintf(stdout, "[SFTP_LOG][%s] {'files_array':[", __FUNCTION__);
			
			if(files_array->size() == 0)
				fprintf(stdout, "]}\n");
			#endif

			if(files_array->size() == 0)
				return 0;

			for(int i = 0; i < files_array->size() - 1; i++)
			{
				#ifdef DEBUG
				fprintf(stdout, "'%s',", files_array->at(i)->path.c_str());
				#endif

				filler(buf, files_array->at(i)->path.c_str(), NULL, 0);		
			}

			const char *last_file =
				files_array->at(files_array->size() - 1)->path.c_str();

			#ifdef DEBUG
			fprintf(stdout, "'%s']}\n", last_file);
			#endif

			filler(buf, last_file, NULL, 0);

			return 0;
		}
		static int sftp_getattr(const char *path, struct stat *stbuf)
		{
			char *remotefile = join_paths(Fuse::server->GetRemotePath(), path);
			int ret_code;

			memset(stbuf, 0, sizeof(struct stat));
			File* f = Fuse::server->GetFile(remotefile, ret_code);

			if(ret_code < 0)
				return -ENOENT;

			if (!strcmp(path, "/"))
			{
				stbuf->st_mode = S_IFDIR | LIBSSH2_SFTP_S_IRWXU |
					LIBSSH2_SFTP_S_IRWXG | LIBSSH2_SFTP_S_IRWXO;
				stbuf->st_nlink = 2;
				stbuf->st_uid 	= fuse_get_context()->uid;
				stbuf->st_gid 	= fuse_get_context()->gid; 
				
				#ifdef DEBUG
				fprintf(stdout, "[SFTP_LOG][%s]"
					" {'path':'%s','type':'directory','ret_code':%d}\n",
					__FUNCTION__, remotefile, ret_code);
				#endif

				return 0;
			}

			stbuf->st_mtime = f->GetLastModifiedTime();
			stbuf->st_atime = f->GetLastAccessTime();
			stbuf->st_size 	= f->GetSize();
			stbuf->st_uid 	= f->GetUID();
			stbuf->st_gid 	= f->GetGID();
			stbuf->st_size 	= f->GetSize();
			stbuf->st_mode  = f->GetPermissions();
			stbuf->st_uid 	= fuse_get_context()->uid;
			stbuf->st_gid 	= fuse_get_context()->gid; 

			if(f->IsDir())
			{
				//stbuf->st_mode = S_IFDIR | f->GetPermissions();
				stbuf->st_nlink = 2;

				#ifdef DEBUG
				fprintf(stdout, "[SFTP_LOG][%s]"
				" {'remotefile':'%s','type':'directory','ret_code':%d}\n",
				__FUNCTION__, remotefile, ret_code);
				#endif

				return 0;
			}
			else if(f->IsFile())
			{
				//stbuf->st_mode = S_IFREG | f->GetPermissions();
				stbuf->st_nlink = 1;

				#ifdef DEBUG
				fprintf(stdout, "[SFTP_LOG][%s]"
					" {'remotefile':'%s','type':'file','ret_code':%d}\n",
					__FUNCTION__, remotefile, ret_code);
				#endif

				return 0;
			}
			else
			{
				stbuf->st_nlink = 1;

				#ifdef DEBUG
				fprintf(stdout, "[SFTP_LOG][%s]"
					" {'remotefile':'%s','type':'other','ret_code':%d}\n",
					__FUNCTION__, remotefile, ret_code);
				#endif

				return 0;
			}
		}
		static int sftp_open(const char *path, struct fuse_file_info *fi)
		{
			char *remotefile = join_paths(Fuse::server->GetRemotePath(), path);
			int ret_code;

			File* f = Fuse::server->GetFile(remotefile, ret_code);

			return ret_code;
		}
		static int sftp_read(const char *path, char *buf, size_t size,
							 off_t offset, struct fuse_file_info *fi)
		{
			(void) fi;

			char *remotefile = join_paths(Fuse::server->GetRemotePath(), path);

			#ifdef DEBUG
			fprintf(stdout, "[SFTP_LOG][%s]" 
				" {'remotefile':'%s','offset':%lu,'size':%lu}\n",
				__FUNCTION__, remotefile, offset, size);
			#endif

			size = Fuse::server->ReadFile(remotefile, buf, size, offset);

			return size;
		}
		static char* join_paths(const char *p1, const char *p2)
		{
			char *remotefile = new char[2048];
			strcpy(remotefile, p1);
			remotefile[strlen(remotefile) - 1] = '\0';
			strcat(remotefile, p2);
			return remotefile;
		}
		static int sftp_mkdir(const char *path, mode_t mode)
		{
			char *remotepath = join_paths(Fuse::server->GetRemotePath(), path);

			#ifdef DEBUG
			fprintf(stdout, "[SFTP_LOG][%s] {'remotepath':'%s','mode':%o}\n",
				__FUNCTION__, remotepath, mode);
			#endif

			if(Fuse::server->CreateDirectory(remotepath, mode) != 0)
			{
				fprintf(stdout, "[SFTP_LOG][%s] Could not create folder\n", 
					__FUNCTION__);
			}

			return 0;
		}
		static int sftp_write(const char *path, const char *buffer, size_t size,
			off_t offset, struct fuse_file_info *fi)
		{
			(void) fi;

			char *remotefile = join_paths(Fuse::server->GetRemotePath(), path);

			#ifdef DEBUG
			fprintf(stdout, "[SFTP_LOG][%s]" 
				" {'remotefile':'%s','offset':%lu,'size':%lu}\n",
				__FUNCTION__, remotefile, offset, size);
			#endif

			size = Fuse::server->WriteFile(remotefile, buffer, size, offset);

			return size;
		}
		static int sftp_chown(const char *path, uid_t uid, gid_t gid)
		{
			char *remotefile = join_paths(Fuse::server->GetRemotePath(), path);

			#ifdef DEBUG
			fprintf(stdout, "[SFTP_LOG][%s]" 
				" {'remotefile':'%s','uid':%d,'gid':%d}\n",
				__FUNCTION__, remotefile, uid, gid);
			#endif

			if(!Fuse::server->ChangeOwnership(remotefile, uid, gid))
				return 0;
			return -ENOENT;
		}
		static int sftp_rmdir(const char *path)
		{
			char *remotepath = join_paths(Fuse::server->GetRemotePath(), path);

			#ifdef DEBUG
			fprintf(stdout, "[SFTP_LOG][%s] {'remotepath':'%s'}\n",
					__FUNCTION__, remotepath);
			#endif

			return Fuse::server->DeleteDirectory(remotepath);
		}
	public:
		static int Init(char* argv0, Server *server)
		{	
			Fuse::server = server;
			args.argc = 5;
			args.argv = new char*[args.argc + 1];
			args.argv[0] = argv0;
			args.argv[1] = Fuse::server->GetMountPoint();

			args.argv[2] = new char[2];
			args.argv[3] = new char[12];
			args.argv[4] = new char[2];

			strcpy(args.argv[2], "-o");
			strcpy(args.argv[3], "auto_unmount");
			strcpy(args.argv[4], "-d");
			
			args.argv[5] = NULL;
			
			Fuse::remotepath_length = strlen(Fuse::server->GetRemotePath());

			operations.readdir 	= sftp_readdir;
			operations.getattr 	= sftp_getattr;
			operations.open 	= sftp_open;
			operations.read 	= sftp_read;
			operations.mkdir 	= sftp_mkdir;
			operations.write 	= sftp_write;
			operations.mknod	= sftp_mknod;
			operations.setxattr = sftp_setattr;
			operations.unlink	= sftp_unlink;
			operations.chown	= sftp_chown;
			operations.chmod	= sftp_chmod;
			operations.rmdir 	= sftp_rmdir;
			return fuse_main(args.argc, args.argv, &operations, NULL);
		}
};
int 					Fuse::remotepath_length;
Server 					*Fuse::server;
struct fuse_args 		Fuse::args;
struct fuse_operations 	Fuse::operations;

void PrintHelp(char *program)
{
	printf("%s\t[--remotepath <path>]\n", strchr(program, '/') + 1);
	printf("\t[--mountpoint <path>]\n");
	printf("\t[username@]server[:port]\n");
}

Server* ParseArgs(int argc, char** argv)
{
	Server *params = new Server();
	params->SetPort(22);
	if(argc <= 1)
	{
		fprintf(stderr, "Invalid arguments!\n");
		exit(1);
	}
	for(int i = 1; i < argc; i++)
	{
		if(!strcmp(argv[i], "--mountpoint"))
		{
			if(i + 1 >= argc)
			{
				fprintf(stderr, "Invalid arguments!\n");
				exit(1);
			}
			params->SetMountPoint(argv[i+1]);
			i += 1;
		}
		else if(!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h"))
		{
			PrintHelp(argv[0]);
			exit(0);
		}
		else
		{
			if(char* user = strchr(argv[i], '@'))
			{
				user[0] = '\0';
				params->SetUsername(argv[i]);
				argv[i] = user + 1;
			}
			if(char* port = strchr(argv[i], ':'))
			{
				params->SetPort(port + 1);
				port[0] = '\0';
			}
			struct hostent *address = gethostbyname(argv[i]);
			if(strstr(address->h_name, "localdomain"))
			{
				fprintf(stderr, "Invalid address!\n");
				exit(1);
			}
			params->SetAddress(address);
		}
	}

	return params;
}

int main(int argc, char** argv)
{
	Server *server = ParseArgs(argc, argv);
	server->InitServerConnection();
	server->InitSSHConnection();
	server->ReadCredentials();
	server->SSHAuth();
	server->InitSFTPSession();
	server->InitRemotePath();
	Fuse::Init(argv[0], server);
	server->CloseServerConnection();
}
