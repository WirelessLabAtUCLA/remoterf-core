from ..grpc import grpc_pb2, grpc_pb2_grpc
import numpy as np

def unmap_arg(arg):
    if arg.HasField('int64_value'):
        return arg.int64_value
    elif arg.HasField('float_value'):
        return arg.float_value
    elif arg.HasField('string_value'):
        return arg.string_value
    elif arg.HasField('bool_value'):
        return arg.bool_value
    elif arg.HasField('real_array'):
        shape = tuple(arg.real_array.shape.dim)
        return np.array(arg.real_array.data, dtype=np.float64).reshape(shape)
    elif arg.HasField('complex_array'):
        shape = tuple(arg.complex_array.shape.dim)
        data = [complex(c.real, c.imag) for c in arg.complex_array.data]
        return np.array(data, dtype=np.complex64).reshape(shape)
    else:
        raise ValueError(f"Unknown argument type during unmapping: {arg}")
    
def map_arg(value):
    arg = grpc_pb2.Argument()
    
    if isinstance(value, (bool, np.bool_)):
        arg.bool_value = bool(value)
    elif isinstance(value, (int, np.integer)):
        arg.int64_value = int(value)
    elif isinstance(value, (float, np.floating)):
        arg.float_value = float(value)
    elif isinstance(value, str):
        arg.string_value = value
    elif isinstance(value, (list, tuple)):
        array = np.asarray(value)
        if array.dtype == object:
            try:
                array = np.stack(value)
            except Exception as exc:
                raise ValueError(f"Cannot map ragged/object array value: {value}") from exc
        return map_arg(array)
    elif isinstance(value, np.ndarray):
        if value.dtype == object:
            raise ValueError(f"Cannot map object-dtype array: {value!r}")
        if np.iscomplexobj(value):
            complex_array = arg.complex_array
            complex_array.shape.dim.extend(value.shape)
            for num in np.asarray(value, dtype=np.complex64).ravel():
                complex_num = complex_array.data.add()
                complex_num.real = float(num.real)
                complex_num.imag = float(num.imag)
        else:
            float_array = arg.real_array
            float_array.shape.dim.extend(value.shape)
            float_array.data.extend(np.asarray(value, dtype=np.float32).ravel())
    else:
        raise ValueError(f"Unknown argument type during mapping: {value}")
    return arg
        
def map_array_proto(np_array):
    arg = grpc_pb2.Argument()
    
    # Check if the array is complex
    if np.iscomplexobj(np_array):
        complex_array = grpc_pb2.ComplexArray()
        for num in np_array.flat:
            complex_number = complex_array.data.add()
            complex_number.real = num.real
            complex_number.imag = num.imag
        arg.complex_array.CopyFrom(complex_array)
    else:
        # Handle as a regular float array
        float_array = grpc_pb2.FloatArray()
        float_array.data.extend(np_array.flat)
        arg.float_array.CopyFrom(float_array)

    return arg

def unmap_array_proto(arg):
    # Check which type of array is available and convert appropriately
    if arg.HasField('complex_array'):
        # Convert ComplexArray to a numpy array of complex numbers
        data = [complex(cn.real, cn.imag) for cn in arg.complex_array.data]
        return np.array(data, dtype=np.complex64)
    elif arg.HasField('float_array'):
        # Convert FloatArray to a numpy array of floats
        return np.array(arg.float_array.data, dtype=np.float32)
    else:
        raise ValueError("Argument does not contain a recognizable array.")
