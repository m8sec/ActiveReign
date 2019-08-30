from io import BytesIO

def get_fileobj(con, share, fpath, filename, max_size, timeout):

    try:
        file_obj = BytesIO()
        file_attributes, file_size = con.retrieveFileFromOffset(share, fpath+filename, file_obj,offset=0, max_length=max_size, timeout=timeout)
        file_obj.seek(0)
        return file_obj
    except Exception as e:
        pass

def close_fileobj(file_obj):
    # Cleanup file object before closing
    file_obj.close()
    del file_obj
