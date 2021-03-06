#ifndef __EXPLODE_IO_HH__
#define __EXPLODE_IO_HH__

#include <stdio.h>
#include <cstddef>
#include <stdint.h>
#include <vector>

#include <sys/types.h>

#include "explode/proper_export.hh"

namespace explode
{
  typedef off_t offset_type;

  class EXPLODE_API input
  {
  public:
    input ();
    virtual ~input ();
    virtual void read_buff (char* buffer, std::size_t size) = 0;
    virtual offset_type tell () = 0;
    virtual offset_type bytes_remains () = 0;
    virtual void seek (offset_type offset) = 0;

    template <typename T>
    void read (T& x)
    {
      union 
      {
	char* bytes;
	T*    words;
      } u;
      u.words = &x;
      this->read_buff (u.bytes, sizeof (T));
    }
  

  private:
    input (const input&);
    input& operator = (const input&);
  };

  // ============================================================

  class EXPLODE_API output
  {
  public:
    output ();
    virtual ~output ();
    virtual void write_buff (const char* buffer, std::size_t size) = 0;
    virtual offset_type tell () = 0;
    virtual void seek (offset_type offset) = 0;

    template <typename T>
    void write (const T& x)
    {
      union 
      {
		const char* bytes;
		const T*    words;
      } u;
      u.words = &x;
      write_buff (u.bytes, sizeof (T));
    }


  private:
    output (const output&);
    output& operator = (const output&);
  };

  // ============================================================

  class EXPLODE_API file_input : public input
  {
  public:
    explicit file_input (const char* path);
    explicit file_input (FILE* file);

    ~file_input ();

    virtual void read_buff (char* buffer, std::size_t size);
    virtual offset_type tell ();
    virtual offset_type bytes_remains ();
    virtual void seek (offset_type offset);

  private:
    bool m_owner;
    FILE* m_file;
  };
  // ============================================================
  class EXPLODE_API inmem_input : public input
  {
  public:
	  inmem_input(const unsigned char* data, std::size_t size);
	  
	  virtual void read_buff (char* buffer, std::size_t size);
	  virtual offset_type tell();
	  virtual offset_type bytes_remains();
	  virtual void seek(offset_type offset);
  private:
	  const unsigned char* m_data;
	  const std::size_t    m_size;
	  std::size_t          m_ptr;
  };

  // ============================================================
  class EXPLODE_API file_output : public output
  {
  public:
    explicit file_output (const char* path);
    explicit file_output (FILE* file);

    ~file_output ();

    virtual void write_buff (const char* buffer, std::size_t size);
    virtual offset_type tell ();
    virtual void seek (offset_type offset);

  private:
    bool m_owner;
    FILE* m_file;
  };
  // ============================================================
  class EXPLODE_API inmem_output : public output
  {
  public:
	  explicit inmem_output(std::vector <char>& out_buff);

	  virtual void write_buff (const char* buffer, std::size_t size);
	  virtual offset_type tell();
	  virtual void seek(offset_type offset);

  private:
	  std::vector <char>& m_buff;
	  std::size_t m_ptr;
  };
} // ns explode



#endif
