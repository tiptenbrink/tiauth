use std::{marker::PhantomData, sync::Arc};

use crate::{ByteOwned, BytePacked, ByteSerial};



trait AsBytes<T: ByteSerial> {
    fn as_bytes(&self) -> &[u8];
}

impl<'a, T: ByteSerial> AsBytes<T> for &'a BytePacked<T> {
    fn as_bytes(&self) -> &[u8] {
        BytePacked::<T>::as_bytes(&self)
    }
}

impl<T: ByteSerial> AsBytes<T> for ByteOwned<T> {
    fn as_bytes(&self) -> &[u8] {
        ByteOwned::<T>::as_packed(&self).as_bytes()
    }
}


struct ProofTest<'a, T: ByteSerial, B: ByteStructure<'a, T>> {
    data: B,
    phantom: PhantomData<&'a T>
}

impl<'a, T: ByteSerial, B: ByteStructure<'a, T>> ProofTest<'a, T, B>
where
    T: ByteSerial,
{
    fn new(
        data: B,
    ) -> Self {
        Self {
            data,
            phantom: PhantomData
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        rmp::encode::write_bin(&mut buf, self.data.as_bytes()).unwrap();

        buf
    }
}