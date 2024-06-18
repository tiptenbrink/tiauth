use terrors::OneOf;

pub trait WrapErrorOneOf<T, E, Target> {
    fn to_one_of_into(self) -> Result<T, OneOf<(Target,)>>;

    fn to_one_of_two<O>(self) -> Result<T, OneOf<(Target, O)>>;

    fn to_one_of_twond<O>(self) -> Result<T, OneOf<(O, Target)>>;
}

impl<T, E, Target> WrapErrorOneOf<T, E, Target> for Result<T, E>
where
    E: Into<Target> + Send + Sync + 'static,
    Target: Send + Sync + 'static,
{
    fn to_one_of_into(self) -> Result<T, OneOf<(Target,)>> {
        self.map_err(|e| e.into()).map_err(OneOf::from)
    }

    fn to_one_of_two<O>(self) -> Result<T, OneOf<(Target, O)>> {
        let as_one_of = self.to_one_of_into();
        as_one_of.map_err(OneOf::broaden)
    }

    fn to_one_of_twond<O>(self) -> Result<T, OneOf<(O, Target)>> {
        let as_one_of = self.to_one_of_into();
        as_one_of.map_err(OneOf::broaden)
    }
}

pub trait OneOfTo<T, E> {
    fn to_one_of(self) -> Result<T, OneOf<(E,)>>;

    fn into_one_of<I>(self) -> Result<T, OneOf<(I,)>>
    where
        I: From<E> + 'static;
}

impl<T, E> OneOfTo<T, E> for Result<T, E>
where
    E: 'static,
{
    fn to_one_of(self) -> Result<T, OneOf<(E,)>> {
        self.map_err(|e| OneOf::new(e))
    }

    fn into_one_of<I>(self) -> Result<T, OneOf<(I,)>>
    where
        I: From<E> + 'static,
    {
        self.map_err(|e| OneOf::new(I::from(e)))
    }
}
